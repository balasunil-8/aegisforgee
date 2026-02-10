# 🚀 First-Time Setup Guide

Welcome to AegisForge! This guide will help you get started after installation.

---

## ✅ Post-Installation Checklist

### 1. Verify Installation

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\Activate.ps1  # Windows PowerShell

# Check application starts
python aegisforge_api.py
```

Visit **http://localhost:5000** in your browser.

### 2. Test API Health

```bash
# Using curl
curl http://localhost:5000/api/health

# Expected response:
{
  "status": "healthy",
  "version": "2.0",
  "database": "connected"
}
```

### 3. Run Initial Tests

```bash
# Run endpoint tests
python test_endpoints.py

# You should see:
# ✓ All tests passed
```

---

## 🔧 Initial Configuration

### Environment Settings

Review and customize your `.env` file:

```bash
# Development vs Production
FLASK_ENV=development  # Change to 'production' for deployment
DEBUG=True             # Set to False in production

# Security Keys (CHANGE THESE!)
SECRET_KEY=your-unique-secret-key-here
JWT_SECRET_KEY=your-unique-jwt-secret-here

# Features
CTF_MODE=True
LEADERBOARD_ENABLED=True
RATE_LIMIT_ENABLED=True

# Database
DATABASE_URL=sqlite:///instance/aegisforge.db
```

### Generate Secure Keys

```python
# Run this to generate secure random keys
python -c "import secrets; print(secrets.token_hex(32))"
```

Copy the output and update `SECRET_KEY` and `JWT_SECRET_KEY` in `.env`.

---

## 👤 Create Your First User

### Option 1: API Registration

```bash
# Register a new user
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePass123!",
    "email": "admin@example.com"
  }'
```

### Option 2: Using Python Script

Create a user directly:

```python
# create_user.py
from aegisforge_api import app, db
from models.user import User
from werkzeug.security import generate_password_hash

with app.app_context():
    user = User(
        username="admin",
        email="admin@example.com",
        password_hash=generate_password_hash("SecurePass123!")
    )
    db.session.add(user)
    db.session.commit()
    print(f"User created: {user.username}")
```

Run:
```bash
python create_user.py
```

### Login

```bash
# Login to get JWT token
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePass123!"
  }'

# Save the returned token for authenticated requests
```

---

## 🎯 Explore the Platform

### 1. Understand Dual-Mode Architecture

AegisForge has two operational modes:

**Red Team (Vulnerable) Mode**:
- `/api/vulnerable/*` - Intentionally vulnerable endpoints
- Learn about vulnerabilities by exploiting them
- Understand attack techniques

**Blue Team (Secure) Mode**:
- `/api/secure/*` - Hardened implementations
- Learn defensive techniques
- See secure coding practices

### 2. Basic API Navigation

```bash
# List all endpoints
curl http://localhost:5000/api/endpoints

# Test vulnerable SQL injection
curl "http://localhost:5000/api/vulnerable/sqli?id=1"

# Compare with secure version
curl "http://localhost:5000/api/secure/sqli?id=1"
```

---

## 📚 Essential Concepts

### OWASP Coverage

AegisForge covers:
- **OWASP Web Top 10 2021**: All 10 categories
- **OWASP API Top 10 2023**: All 10 categories

Major vulnerability categories:
1. Broken Access Control (BOLA, BFLA)
2. Cryptographic Failures
3. Injection (SQL, Command, XSS)
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable Components
7. Authentication Failures
8. Integrity Failures
9. Logging Failures
10. Server-Side Request Forgery (SSRF)

### CTF Challenge System

AegisForge includes 18 progressive challenges:

```bash
# Start CTF mode
python ctf_manager.py

# View challenges
curl http://localhost:5000/api/ctf/challenges

# Submit flag
curl -X POST http://localhost:5000/api/ctf/submit \
  -H "Content-Type: application/json" \
  -d '{"challenge_id": 1, "flag": "AEGIS{...}"}'
```

---

## 🛠️ Tool Integration Setup

### Postman Setup

1. **Import Collection**:
   - Open Postman
   - Import → File → Select `postman/AegisForge_Collection.json`

2. **Configure Environment**:
   - Import `postman/AegisForge_Environment.json`
   - Set `base_url` to `http://localhost:5000`
   - Set `token` after logging in

3. **Test Endpoints**:
   - Navigate to folders: Vulnerable, Secure, CTF
   - Send requests to test functionality

### OWASP ZAP Setup

1. **Start ZAP**
2. **Automated Scan**:
   - Tools → Automated Scan
   - URL: `http://localhost:5000`
   - Attack Mode: Standard

3. **Manual Explore**:
   - Configure browser proxy: localhost:8080
   - Browse AegisForge to build site tree
   - Right-click → Attack → Spider/Ajax Spider

See [OWASP_ZAP_GUIDE.md](../../OWASP_ZAP_GUIDE.md) for details.

### Burp Suite Setup

1. **Configure Proxy**:
   - Proxy → Options → Proxy Listeners → 127.0.0.1:8080

2. **Configure Browser**:
   - Set proxy to localhost:8080
   - Install Burp CA certificate

3. **Test Target**:
   - Target → Site Map
   - Browse to http://localhost:5000
   - View intercepted requests

See [BURP_SUITE_GUIDE.md](../../BURP_SUITE_GUIDE.md) for details.

---

## 📖 Learning Path Selection

Choose your learning path based on your experience:

### Beginner Path
1. **Start with Basics**:
   - Read API documentation
   - Understand vulnerable vs secure modes
   - Test simple endpoints (SQL injection, XSS)

2. **First CTF Challenges**:
   - Complete challenges 1-6 (Easy difficulty)
   - Learn basic exploitation techniques

3. **Tool Integration**:
   - Set up Postman
   - Run automated Postman tests

### Intermediate Path
1. **OWASP Deep Dive**:
   - Study each OWASP category
   - Test both vulnerable and secure versions
   - Understand the differences

2. **CTF Challenges**:
   - Complete challenges 7-12 (Medium difficulty)
   - Use multiple tools (Burp, ZAP)

3. **Custom Exploits**:
   - Write custom Python scripts
   - Chain multiple vulnerabilities

### Advanced Path
1. **Complex Vulnerabilities**:
   - Server-Side Request Forgery (SSRF)
   - Insecure Deserialization
   - XML External Entities (XXE)

2. **Advanced CTF**:
   - Complete challenges 13-18 (Hard difficulty)
   - Compete on leaderboard

3. **Defense Implementation**:
   - Study secure implementations
   - Contribute to the project

See [learning-paths.md](learning-paths.md) for detailed curriculum.

---

## 🔍 Quick Reference

### Common Endpoints

```bash
# Health check
GET /api/health

# Authentication
POST /api/register
POST /api/login
POST /api/logout

# Vulnerable endpoints
GET /api/vulnerable/sqli
GET /api/vulnerable/xss
POST /api/vulnerable/bola
POST /api/vulnerable/command-injection

# Secure endpoints (same paths)
GET /api/secure/sqli
GET /api/secure/xss

# CTF
GET /api/ctf/challenges
POST /api/ctf/submit
GET /api/leaderboard
```

### Useful Commands

```bash
# View logs
tail -f logs/aegisforge.log

# Reset database
rm instance/aegisforge.db
python init_db.py

# Run tests
python test_endpoints.py

# Check running processes
# Linux/macOS
lsof -i :5000
# Windows
netstat -ano | findstr :5000
```

---

## 🎓 Recommended Next Steps

1. **Day 1: Exploration**
   - [ ] Test all major endpoints
   - [ ] Register user account
   - [ ] Complete first CTF challenge
   - [ ] Set up Postman

2. **Day 2: Deep Dive**
   - [ ] Study SQL injection examples
   - [ ] Compare vulnerable vs secure
   - [ ] Complete 3 CTF challenges
   - [ ] Set up OWASP ZAP

3. **Week 1: Mastery**
   - [ ] Cover all OWASP categories
   - [ ] Complete 10+ CTF challenges
   - [ ] Set up all tools
   - [ ] Write custom exploits

---

## 📚 Documentation Resources

Essential reading:
- [README.md](../../README.md) - Project overview
- [API_DOCUMENTATION.md](../../API_DOCUMENTATION.md) - Complete API reference
- [OWASP_COVERAGE_MATRIX.md](../../OWASP_COVERAGE_MATRIX.md) - Vulnerability mapping
- [learning-paths.md](learning-paths.md) - Structured curriculum

Tool guides:
- [POSTMAN_GUIDE.md](../../POSTMAN_GUIDE.md)
- [OWASP_ZAP_GUIDE.md](../../OWASP_ZAP_GUIDE.md)
- [BURP_SUITE_GUIDE.md](../../BURP_SUITE_GUIDE.md)
- [SQLMAP_GUIDE.md](../../SQLMAP_GUIDE.md)

---

## 🆘 Getting Help

### Troubleshooting

See [common-issues.md](../troubleshooting/common-issues.md) for solutions to frequent problems.

### Support Channels

- **Documentation**: Check docs/ directory
- **GitHub Issues**: Report bugs or request features
- **Community**: Join discussions on GitHub

---

## ✨ Tips for Success

1. **Start Simple**: Begin with basic vulnerabilities before advanced topics
2. **Compare Modes**: Always compare vulnerable vs secure implementations
3. **Take Notes**: Document what you learn
4. **Use Tools**: Integrate Postman, Burp, or ZAP early
5. **Read Code**: Review the source code to understand implementations
6. **Be Patient**: Security is complex - take your time
7. **Practice Ethics**: Only test authorized systems

---

## 🎉 You're Ready!

Your AegisForge setup is complete. Happy learning!

**First challenge**: Can you exploit the SQL injection vulnerability at `/api/vulnerable/sqli`?

See [learning-paths.md](learning-paths.md) for your structured learning journey.

---

**Need help? Check [common-issues.md](../troubleshooting/common-issues.md) or open a GitHub issue.**
