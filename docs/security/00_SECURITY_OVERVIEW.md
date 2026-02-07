# Security Overview

## 🎓 Welcome to AegisForge Security Documentation

This documentation provides comprehensive guidance on security practices, credential management, and deployment strategies for the AegisForge platform.

---

## 📚 Documentation Structure

1. **[00_SECURITY_OVERVIEW.md](00_SECURITY_OVERVIEW.md)** - This document
2. **[01_ENVIRONMENT_SETUP.md](01_ENVIRONMENT_SETUP.md)** - Setting up your environment
3. **[02_CREDENTIAL_MANAGEMENT.md](02_CREDENTIAL_MANAGEMENT.md)** - Managing credentials and secrets
4. **[03_PRODUCTION_DEPLOYMENT.md](03_PRODUCTION_DEPLOYMENT.md)** - Production deployment guide
5. **[04_GITGUARDIAN_RESPONSE.md](04_GITGUARDIAN_RESPONSE.md)** - GitGuardian alert response
6. **[05_BEST_PRACTICES.md](05_BEST_PRACTICES.md)** - Security best practices

---

## 🎯 Platform Purpose

**AegisForge is an educational security platform** designed to teach application security through hands-on practice.

### Key Components:

#### 🔴 Red Team (Vulnerable Endpoints)
- Intentionally vulnerable code
- Demonstrates common security flaws
- Educational exploitation examples
- Located at `/api/red/*` endpoints

#### 🔵 Blue Team (Secure Endpoints)
- Properly secured implementations
- Demonstrates security best practices
- Shows how to fix vulnerabilities
- Located at `/api/blue/*` endpoints

---

## ⚠️ Critical Security Warnings

### For Students & Learners

✅ **DO:**
- Use in local lab environments
- Practice on your own infrastructure
- Learn from both vulnerable and secure code
- Follow ethical hacking guidelines

❌ **DO NOT:**
- Deploy Red Team code to production
- Use on systems you don't own
- Share test credentials as real secrets
- Perform unauthorized security testing

---

## 🔐 Security Philosophy

### Educational Transparency

We believe in **security through education**, not security through obscurity.

**Our Approach:**
1. Show both vulnerable and secure implementations
2. Explain why vulnerabilities exist
3. Demonstrate proper security controls
4. Provide clear documentation

---

## 🛡️ Built-in Security Features

### Infrastructure Security

- ✅ Environment variable support
- ✅ Secure configuration management
- ✅ Comprehensive .gitignore
- ✅ Security documentation
- ✅ Credential management utilities

### Blue Team Security Controls

- ✅ Parameterized SQL queries (prevents SQL injection)
- ✅ Authorization checks (prevents IDOR)
- ✅ Database locking (prevents race conditions)
- ✅ Output encoding (prevents XSS)
- ✅ Field whitelisting (prevents mass assignment)
- ✅ CSRF tokens (prevents CSRF)
- ✅ Secure session management
- ✅ Rate limiting
- ✅ Security headers

---

## 📖 Quick Start Security Guide

### 1. Environment Setup
```bash
# Copy environment template
cp .env.example .env

# Edit with your values
nano .env

# NEVER commit .env to version control!
```

### 2. Review Test Credentials
- See `CREDENTIALS.md` for all test credentials
- All credentials are publicly documented
- Use environment variables to customize

### 3. Understand Red vs Blue
- **Red Team** = Vulnerable (for learning attacks)
- **Blue Team** = Secure (for learning defense)
- Never deploy Red Team to production

---

## 📚 Additional Resources

### Internal Documentation
- `/SECURITY.md` - Security policy
- `/CREDENTIALS.md` - Test credentials
- `/README.md` - Platform overview
- `.env.example` - Configuration template

### External Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---

**Last Updated:** February 2026
**Version:** 1.0
