## 🔐 Security Checklist

**Please review the following before submitting your PR:**

### Code Changes
- [ ] No hardcoded credentials added (use environment variables)
- [ ] No sensitive data in commit messages or code comments
- [ ] No API keys or secrets committed
- [ ] No new database credentials in source code

### Red Team vs Blue Team
- [ ] Changes clearly labeled as Red Team (vulnerable) or Blue Team (secure)
- [ ] Red Team endpoints have clear vulnerability warnings in comments
- [ ] Blue Team endpoints implement proper security controls

### Environment Variables
- [ ] New configuration added to `.env.example` if needed
- [ ] No `.env` files committed
- [ ] Configuration documented in appropriate config.py

### Documentation
- [ ] Security implications documented
- [ ] Updated CREDENTIALS.md if test credentials changed
- [ ] Updated relevant security documentation in `docs/security/`

### Testing
- [ ] Code tested locally
- [ ] Security controls verified (for Blue Team changes)
- [ ] No regression in existing functionality

### Dependencies
- [ ] No known vulnerable dependencies added
- [ ] Dependencies justified and documented

---

## 📝 Description

**Please describe your changes:**

<!-- A clear description of what this PR does -->

---

## 🎯 Type of Change

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🔐 Security improvement (Blue Team)
- [ ] 🎓 Educational content (Red Team vulnerabilities)

---

## 🧪 Testing

**How has this been tested?**

- [ ] Manual testing
- [ ] Automated tests added/updated
- [ ] Tested with Burp Suite/OWASP ZAP
- [ ] Tested exploitation (Red Team)
- [ ] Tested defense (Blue Team)

---

## 📸 Screenshots (if applicable)

<!-- Add screenshots to help explain your changes -->

---

## ✅ Final Checks

- [ ] Code follows the project's style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No warnings or errors in console
- [ ] Tested in development environment

---

**Thank you for contributing to AegisForge! 🛡️**
