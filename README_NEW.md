# 🛡️ AegisForge v1.0 - Complete Security Testing Platform

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/balasunil-8/aegisforgee)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red.svg)](https://owasp.org/www-project-top-ten/)
[![Documentation](https://img.shields.io/badge/docs-650%2B%20pages-brightgreen.svg)](docs/)

> **The ultimate dual-mode security learning platform with 102K+ lines of code, 13 vulnerabilities, and complete OWASP coverage**

---

## 🎯 What is AegisForge?

AegisForge is a professional-grade security testing and education platform featuring **dual-mode architecture** (Red Team vulnerable endpoints + Blue Team secure implementations) with complete OWASP coverage, CTF challenges, ML-based threat detection, and integrated security analytics.

Perfect for:
- 🎓 **Security Students** - Learn by doing with hands-on vulnerable applications
- 🔒 **Penetration Testers** - Practice exploitation techniques in a safe environment
- 👨‍💻 **Developers** - Understand vulnerabilities and learn secure coding practices
- 🏢 **Training Programs** - Complete curriculum with 650+ pages of documentation

---

## ✨ Key Features

### 🎯 Dual-Mode Architecture
- **Red Team Mode**: 40+ intentionally vulnerable endpoints covering all OWASP categories
- **Blue Team Mode**: 52+ hardened secure implementations with defense-in-depth
- **Side-by-Side Comparison**: Learn by contrasting vulnerable vs secure code

### 🏦 Two Complete Applications

#### **SecureBank** (22,295 lines)
Modern banking application with:
- User authentication & session management
- Account transfers & transaction history
- Password reset & profile management
- **13 intentional vulnerabilities** across OWASP categories

#### **ShopVuln** (23,604 lines)
E-commerce platform featuring:
- Product catalog & shopping cart
- Order processing & payment handling
- User reviews & ratings
- **13 intentional vulnerabilities** for security testing

### 🔒 Complete OWASP Coverage
- ✅ **OWASP Web Top 10 2021**: 100% coverage
- ✅ **OWASP API Top 10 2023**: 100% coverage
- ✅ Real-world vulnerability examples with exploitation paths
- ✅ Detailed remediation guides for each vulnerability

### 🎮 CTF Challenge System
- **18 Progressive Challenges**: From beginner to advanced (2,700 total points)
- **Real-Time Leaderboard**: Competitive scoring with timestamps
- **Difficulty Levels**: Easy (100pts), Medium (200pts), Hard (300pts)
- **Auto-Validation**: Instant feedback on challenge completion

### 🛠️ Professional Security Tools Integration
- **Burp Suite** - Web application security testing
- **OWASP ZAP** - Automated vulnerability scanning
- **SQLmap** - Automated SQL injection testing
- **Postman** - API testing with ready-to-use collections
- **FFuf** - Web fuzzing and content discovery

---

## 📊 Platform Statistics

| Metric | Count |
|--------|-------|
| **Total Lines of Code** | 102,048+ |
| **Applications** | 2 (SecureBank, ShopVuln) |
| **Vulnerabilities** | 13 unique types |
| **Files** | 250+ |
| **Documentation Pages** | 650+ |
| **OWASP Categories Covered** | 13 |
| **CTF Challenges** | 18 |
| **Security Tools Integrated** | 5+ |

---

## 🚀 Quick Start

### System Requirements

**Minimum:**
- Python 3.8+
- 4GB RAM
- 3GB disk space
- Windows, Linux, or macOS

**Recommended:**
- Python 3.10+
- 8GB RAM
- 5GB disk space

### One-Command Installation

**Windows:**
```batch
scripts\windows\install.bat
```

**Linux/Mac:**
```bash
chmod +x scripts/linux/install.sh
./scripts/linux/install.sh
```

### Launch All Applications
**Windows:**
```batch
scripts\windows\start_all_apps.bat
```

**Linux/Mac:**
```bash
./scripts/linux/start_all_apps.sh
```

### Access Applications

| Application | URL | Purpose |
|------------|-----|---------|
| SecureBank Red | http://localhost:5000 | Vulnerable banking app |
| SecureBank Blue | http://localhost:5001 | Secure banking app |
| ShopVuln Red | http://localhost:5002 | Vulnerable e-commerce |
| ShopVuln Blue | http://localhost:5003 | Secure e-commerce |

### Test Credentials

| Username | Password | Role |
|----------|----------|------|
| alice | password123 | Standard User |
| bob | securepass456 | Standard User |
| admin | admin123 | Administrator |

---

## 📚 Learning Paths

### 🟢 Beginner Path (4 weeks)
1. **Week 1**: Setup & SQL Injection basics
2. **Week 2**: XSS & CSRF fundamentals
3. **Week 3**: Authentication & session management
4. **Week 4**: Basic CTF challenges (Easy level)

**Start here:** [First Time Setup](docs/getting-started/first-time-setup.md)

### 🟡 Intermediate Path (6 weeks)
1. **Weeks 1-2**: All beginner vulnerabilities
2. **Week 3**: IDOR & broken access control
3. **Week 4**: Mass assignment & injection attacks
4. **Week 5**: Advanced exploitation with tools
5. **Week 6**: Medium CTF challenges

**Start here:** [Your First Vulnerability](docs/getting-started/your-first-vulnerability.md)

### 🔴 Advanced Path (8 weeks)
1. **Weeks 1-4**: Complete beginner & intermediate
2. **Week 5**: Race conditions & complex exploits
3. **Week 6**: Tool automation (Burp, ZAP, SQLmap)
4. **Week 7**: Chaining vulnerabilities
5. **Week 8**: Hard CTF challenges & leaderboard

**Start here:** [Learning Paths](docs/getting-started/learning-paths.md)

---

## 🗂️ Project Structure

```
aegisforgee/
├── backend/
│   ├── apps/
│   │   ├── securebank/          # Banking application (22K lines)
│   │   │   ├── securebank_red_api.py    # Vulnerable endpoints
│   │   │   ├── securebank_blue_api.py   # Secure endpoints
│   │   │   ├── database.py              # Database schema
│   │   │   └── seed_data.py             # Test data
│   │   └── shopvuln/            # E-commerce application (23K lines)
│   │       ├── shopvuln_red_api.py      # Vulnerable endpoints
│   │       ├── shopvuln_blue_api.py     # Secure endpoints
│   │       ├── database.py              # Database schema
│   │       └── seed_data.py             # Test data
│   ├── owasp/                   # OWASP vulnerability modules
│   └── utils/                   # Shared utilities
├── docs/                        # 650+ pages of documentation
│   ├── apps/                    # Application-specific docs
│   ├── security/                # Security guides
│   ├── vulnerabilities/         # Vulnerability details
│   ├── installation/            # Setup guides
│   └── getting-started/         # Beginner tutorials
├── scripts/                     # Automation scripts
│   ├── windows/                 # Windows batch files
│   ├── linux/                   # Linux/Mac shell scripts
│   └── python/                  # Cross-platform Python scripts
├── ctf_challenges/              # CTF challenge definitions
└── tools/                       # Security tool integrations
```

---

## 🔍 13 Vulnerability Categories

1. **SQL Injection** - Database manipulation via user input
2. **Cross-Site Scripting (XSS)** - Stored, reflected, and DOM-based
3. **Cross-Site Request Forgery (CSRF)** - Unauthorized actions
4. **Broken Authentication** - Session hijacking & credential attacks
5. **Insecure Direct Object References (IDOR)** - Unauthorized data access
6. **Security Misconfiguration** - Default credentials & settings
7. **Sensitive Data Exposure** - Unencrypted sensitive information
8. **Broken Access Control** - Privilege escalation
9. **Command Injection** - OS command execution
10. **XML External Entity (XXE)** - XML parser exploitation
11. **Server-Side Request Forgery (SSRF)** - Internal service access
12. **Mass Assignment** - Unintended property modification
13. **Race Conditions** - Time-of-check time-of-use vulnerabilities

---

## 🛠️ Tools & Resources

### Integrated Security Tools
- 🔥 **Burp Suite Community** - [Setup Guide](BURP_SUITE_GUIDE.md)
- 🔍 **OWASP ZAP** - [Setup Guide](OWASP_ZAP_GUIDE.md)
- 💉 **SQLmap** - [Setup Guide](SQLMAP_GUIDE.md)
- 🚀 **Postman** - [Collection Guide](POSTMAN_GUIDE.md)
- ⚡ **FFuf** - [Fuzzing Guide](FFUF_GUIDE.md)

### Documentation
- 📖 [Quick Start Guide](QUICKSTART.md) - Get started in 5 minutes
- 📘 [Installation Guide](INSTALL.md) - Detailed setup instructions
- 📙 [API Documentation](API_DOCUMENTATION.md) - Complete API reference
- 📕 [Vulnerability Guide](docs/vulnerabilities/) - Exploitation & remediation
- 📗 [Contributing Guide](CONTRIBUTING.md) - How to contribute

---

## 🚀 Roadmap

### Version 2.1 (Q2 2026) - Modern API Security
- GraphQL vulnerability examples (5 vulnerabilities)
- WebSocket security testing (4 vulnerabilities)
- JWT exploitation scenarios (6 attack types)
- Advanced SSRF techniques (5 techniques)
- Mobile API security patterns (7 patterns)
- **New Application**: APISecLab (Modern API platform)
- **Documentation**: 27+ new guides (400+ pages)

### Version 3.0 (Q4 2026) - AI & Analytics
- Web UI Analytics Dashboard (React + D3.js)
- Automated Exploit Generation (AI-powered)
- SIEM Integration (5 platforms: Splunk, ELK, QRadar, Sentinel, ArcSight)
- Deep Learning Models (4 models, 78-92% accuracy)
- **New Application**: IntelliForge (AI security analysis)
- **Documentation**: 35+ new guides (500+ pages)

**[View Full Roadmap](ROADMAP.md)**

---

## 🤝 Contributing

We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md) to get started.

### Ways to Contribute
- 🐛 Report bugs and issues
- 💡 Suggest new features or vulnerabilities
- 📝 Improve documentation
- 🔧 Submit bug fixes or enhancements
- 🎨 Enhance UI/UX
- 🧪 Add test cases

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY**

AegisForge is designed exclusively for educational purposes and authorized security testing. The vulnerabilities in this platform are intentional and should only be used in controlled environments.

- ✅ Use in lab/test environments
- ✅ Use for educational purposes
- ✅ Use for authorized penetration testing
- ❌ Do NOT use on production systems
- ❌ Do NOT use for unauthorized access
- ❌ Do NOT use for illegal activities

**Users are responsible for compliance with all applicable laws.**

---

## 🙏 Acknowledgments

- OWASP Foundation for security standards and guidelines
- Security community for vulnerability research
- Contributors and testers who helped improve the platform

---

## 📞 Support & Community

- 📧 **Issues**: [GitHub Issues](https://github.com/balasunil-8/aegisforgee/issues)
- 📚 **Documentation**: [docs/](docs/)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/balasunil-8/aegisforgee/discussions)

---

<div align="center">

**Built with ❤️ for the Security Community**

**[Get Started](QUICKSTART.md)** • **[Documentation](docs/)** • **[Roadmap](ROADMAP.md)**

</div>
