# Quick Security Reference

## 🎓 AegisForge Security - Quick Start

**Welcome to AegisForge!** This is your quick security reference guide.

---

## ⚠️ Critical Information

### What is AegisForge?

**Educational security platform** with two types of code:

- 🔴 **Red Team** - Intentionally vulnerable (learn attacks)
- 🔵 **Blue Team** - Properly secured (learn defense)

### Safety Warning

**NEVER deploy Red Team endpoints to production or public internet!**

---

## 🚀 Quick Setup (5 Minutes)

### 1. Clone & Setup
```bash
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
cp .env.example .env
pip install -r requirements.txt
python init_db.py
python aegisforge_api.py
```

### 2. Default Test Credentials

| User | Password | Role |
|------|----------|------|
| alice | password123 | user |
| bob | securepass456 | user |
| admin | admin123 | admin |

**See full list:** `CREDENTIALS.md`

### 3. Explore Endpoints

- **Red Team (Vulnerable):** `/api/red/*`
- **Blue Team (Secure):** `/api/blue/*`

---

## 📚 Key Documentation

| Document | Purpose |
|----------|---------|
| `SECURITY.md` | Security policy and reporting |
| `CREDENTIALS.md` | All test credentials |
| `.env.example` | Configuration template |
| `docs/security/00_SECURITY_OVERVIEW.md` | Security overview |
| `docs/security/01_ENVIRONMENT_SETUP.md` | Environment setup |
| `docs/security/02_CREDENTIAL_MANAGEMENT.md` | Credential management |
| `docs/security/03_PRODUCTION_DEPLOYMENT.md` | Production guide |
| `docs/security/04_GITGUARDIAN_RESPONSE.md` | GitGuardian alert info |
| `docs/security/05_BEST_PRACTICES.md` | Best practices |

---

## 🔐 Security Quick Reference

### Environment Variables

```bash
# Generate secure secret key
python -c "import secrets; print(secrets.token_hex(32))"

# Add to .env
FLASK_SECRET_KEY=<generated-value>
```

### Custom Test Credentials

```bash
# Edit .env
TEST_USER_ALICE_PASSWORD=mycustompassword
TEST_USER_BOB_PASSWORD=anothercustompass
```

### Security Headers (Blue Team)

```python
# Automatically applied to Blue Team endpoints
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Content-Security-Policy
```

---

## 🎯 Common Tasks

### Task: Change Test Password
1. Edit `.env` file
2. Set `TEST_USER_ALICE_PASSWORD=newpassword`
3. Restart application

### Task: Enable Only Blue Team
1. Comment out Red Team imports in main file
2. Set `ENABLE_RED_TEAM=False` in `.env`
3. Restart application

### Task: Generate Strong Secret
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## 🚨 Security Warnings

### DO:
- ✅ Use in local lab environments
- ✅ Read documentation before deploying
- ✅ Use environment variables for secrets
- ✅ Practice on your own infrastructure

### DO NOT:
- ❌ Deploy Red Team to production
- ❌ Commit `.env` files
- ❌ Use on systems you don't own
- ❌ Share as real security issues

---

## 🐛 Quick Troubleshooting

### Issue: Can't login
**Solution:** Check credentials in `CREDENTIALS.md`

### Issue: Secret key error
**Solution:** Set `FLASK_SECRET_KEY` in `.env`

### Issue: Database error
**Solution:** Run `python init_db.py`

---

## 📞 Need Help?

- **Documentation:** `docs/security/`
- **Security Issues:** See `SECURITY.md`
- **Questions:** GitHub Discussions
- **Bugs:** GitHub Issues

---

## 🎓 Learning Paths

### Beginner
1. Read `docs/security/00_SECURITY_OVERVIEW.md`
2. Try Red Team endpoints (learn vulnerabilities)
3. Compare with Blue Team endpoints (learn fixes)

### Intermediate
1. Practice exploitation techniques
2. Implement security fixes
3. Review security best practices

### Advanced
1. Analyze vulnerable vs secure code
2. Develop custom exploits
3. Create additional Blue Team implementations

---

## ✅ Quick Security Checklist

Before any deployment:

- [ ] Read `SECURITY.md`
- [ ] Review `CREDENTIALS.md`
- [ ] Configure `.env` file
- [ ] Disable Red Team endpoints (if production)
- [ ] Generate strong secrets
- [ ] Enable HTTPS
- [ ] Set up monitoring
- [ ] Review `docs/security/03_PRODUCTION_DEPLOYMENT.md`

---

## 🔑 Essential Commands

```bash
# Generate secret key
python -c "import secrets; print(secrets.token_hex(32))"

# Generate password
python -c "import secrets; print(secrets.token_urlsafe(16))"

# Check dependencies
pip list --outdated

# Security scan
bandit -r .

# Start application
python aegisforge_api.py
```

---

## 📊 Platform Overview

```
AegisForge
├── Red Team (Vulnerable)
│   ├── SQL Injection
│   ├── IDOR
│   ├── Race Conditions
│   ├── XSS
│   ├── Mass Assignment
│   └── CSRF
│
└── Blue Team (Secure)
    ├── Parameterized Queries
    ├── Authorization Checks
    ├── Transaction Locking
    ├── Output Encoding
    ├── Field Whitelisting
    └── CSRF Tokens
```

---

## 🎯 Quick Links

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Academy](https://portswigger.net/web-security)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)

---

**Last Updated:** February 2026
**Quick Reference Version:** 1.0
**Full Documentation:** `docs/security/`
