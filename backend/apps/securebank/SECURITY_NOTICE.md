# SecureBank Security Notice

## ⚠️ EDUCATIONAL SECURITY PLATFORM

**SecureBank is an intentionally vulnerable banking application designed for security education.**

---

## 🎓 Purpose

SecureBank demonstrates both **vulnerable (Red Team)** and **secure (Blue Team)** implementations of common web application vulnerabilities:

1. **SQL Injection** - Login bypass and data extraction
2. **IDOR** - Insecure Direct Object References
3. **Race Conditions** - Concurrent transaction vulnerabilities
4. **XSS** - Cross-Site Scripting in transaction notes
5. **Mass Assignment** - Profile update vulnerabilities
6. **CSRF** - Cross-Site Request Forgery

---

## 🔴 Red Team Endpoints (Vulnerable)

**Location:** `securebank_red_api.py`

**WARNING:** These endpoints contain intentional security vulnerabilities!

### Characteristics:
- ❌ SQL injection vulnerabilities
- ❌ No authorization checks (IDOR)
- ❌ No race condition protection
- ❌ No XSS output encoding
- ❌ Mass assignment allowed
- ❌ No CSRF protection
- ❌ Weak secret key
- ❌ Wide-open CORS

**Purpose:** Educational demonstrations of how NOT to build secure applications

**Never deploy these to production!**

---

## 🔵 Blue Team Endpoints (Secure)

**Location:** `securebank_blue_api.py`

**These endpoints demonstrate proper security implementations!**

### Security Features:
- ✅ Parameterized SQL queries
- ✅ Authorization checks
- ✅ Database transaction locking
- ✅ XSS output encoding
- ✅ Field whitelisting
- ✅ CSRF protection
- ✅ Strong secret key (from environment)
- ✅ Restricted CORS

**Purpose:** Educational demonstrations of secure coding practices

---

## 🔐 Test Credentials

### Default Test Users (Red Team)

All credentials are hardcoded in `seed_data.py` for easy setup:

- **alice** / **password123** - Regular user with checking and savings accounts
- **bob** / **securepass456** - Regular user with checking and savings accounts
- **admin** / **admin123** - Administrator account
- **carol** / **carol789** - Regular user with checking and savings accounts

**These credentials are documented in `/CREDENTIALS.md`**

### Why Hardcoded?

1. **Easy Setup** - Users can start learning immediately
2. **Consistent Testing** - Predictable credentials for workshops
3. **Demonstration** - Shows insecure credential management
4. **Educational Value** - Real examples of poor security practices

---

## 🛠️ Using Environment Variables

### For Custom Credentials

1. Copy `.env.example` to `.env`
2. Set your custom passwords:
   ```bash
   TEST_USER_ALICE_PASSWORD=your-custom-password
   TEST_USER_BOB_PASSWORD=your-custom-password
   TEST_USER_ADMIN_PASSWORD=your-custom-password
   TEST_USER_CAROL_PASSWORD=your-custom-password
   ```
3. Never commit `.env` to version control

### For Production (NOT Recommended)

**SecureBank is NOT intended for production use!**

If you must deploy:
1. Use only Blue Team endpoints
2. Disable all Red Team endpoints
3. Use strong randomly generated passwords
4. Enable HTTPS
5. Implement rate limiting
6. Use a Web Application Firewall (WAF)

---

## 📖 Educational Use

### Learning Objectives

**Red Team (Attack):**
- Practice exploiting SQL injection
- Test IDOR vulnerabilities
- Exploit race conditions
- Perform XSS attacks
- Demonstrate mass assignment
- Execute CSRF attacks

**Blue Team (Defense):**
- Understand parameterized queries
- Implement authorization checks
- Use database locking
- Apply output encoding
- Implement field whitelisting
- Add CSRF tokens

---

## ⚖️ Legal & Ethical Notice

**IMPORTANT:**
- Use only in controlled lab environments
- Never deploy Red Team code to production
- Never test vulnerabilities on systems you don't own
- Obtain written permission before security testing
- Follow responsible disclosure practices

**Unauthorized access to computer systems is illegal!**

---

## 📚 Resources

- `/SECURITY.md` - Overall security policy
- `/CREDENTIALS.md` - All test credentials
- `/docs/security/` - Detailed security documentation
- `.env.example` - Environment variable template
- `README.md` - SecureBank overview and usage

---

## 🎯 Summary

**Red Team = Learn to Attack**
**Blue Team = Learn to Defend**

Both are essential for understanding application security!

---

**Last Updated:** February 2026
**Part of:** AegisForge Security Education Platform
