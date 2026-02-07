# Security Policy

## 🎓 Educational Platform Notice

**AegisForge is an intentionally vulnerable web application designed for security education.**

This platform contains:
- ✅ **Red Team** endpoints with intentional vulnerabilities (for learning exploitation)
- ✅ **Blue Team** endpoints with security fixes (for learning defense)
- ⚠️ **Hardcoded test credentials** (for educational demonstrations)
- ⚠️ **Weak configurations** (to demonstrate security misconfigurations)

**⚠️ NEVER deploy Red Team endpoints to production or public internet!**

---

## 🔒 Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## 🚨 Reporting a Security Vulnerability

### What to Report

**Please report actual security issues, NOT intentional vulnerabilities.**

**DO report:**
- ✅ Unintentional vulnerabilities in Blue Team (secure) endpoints
- ✅ Vulnerabilities in the platform infrastructure itself
- ✅ Security issues in deployment configurations
- ✅ Flaws in security documentation or examples

**DO NOT report:**
- ❌ Intentional vulnerabilities in Red Team endpoints (that's the point!)
- ❌ Test credentials in seed data (documented and intentional)
- ❌ Weak configurations in Red Team examples (educational)

### How to Report

**GitHub Security Advisories:** Use the "Security" tab above to report vulnerabilities privately

**Email:** security@aegisforge.local

**Include:**
1. Description of the vulnerability
2. Steps to reproduce
3. Affected component (Red Team vs Blue Team vs Infrastructure)
4. Potential impact
5. Suggested fix (if you have one)

**Response Time:**
- Initial response: Within 48 hours
- Fix timeline: Within 7-30 days depending on severity

---

## 🔐 Test Credentials Explanation

### Why Hardcoded Credentials Exist

AegisForge contains hardcoded test credentials **intentionally** for these reasons:

1. **Educational demonstrations** - Show real examples of credential exposure
2. **Easy setup** - Users can start learning immediately without configuration
3. **Consistent testing** - Predictable credentials for workshop environments
4. **Vulnerability examples** - Demonstrate OWASP A07 (Authentication Failures)

All test credentials are documented in `CREDENTIALS.md`

### Production Use

**If deploying to production:**

1. ✅ Use environment variables (see `.env.example`)
2. ✅ Generate strong random passwords
3. ✅ Enable only Blue Team endpoints
4. ✅ Disable Red Team endpoints completely
5. ✅ Use HTTPS with valid certificates
6. ✅ Enable rate limiting and WAF
7. ✅ Review `docs/security/03_PRODUCTION_DEPLOYMENT.md`

---

## 📚 Security Resources

- `SECURITY.md` - Complete security policy
- `CREDENTIALS.md` - All test credentials
- `docs/security/` - Complete security guides
- `docs/README_SECURITY.md` - Quick security reference
- `.env.example` - Secure configuration template

---

**Last Updated:** February 2026
**Contact:** security@aegisforge.local
