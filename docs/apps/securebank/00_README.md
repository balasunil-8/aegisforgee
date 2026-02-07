# 🏦 SecureBank - Interactive Banking Web Application

**Part of the AegisForge Security Education Platform**

SecureBank is a comprehensive, professional banking web application designed to teach web security vulnerabilities and their defenses through hands-on practice. It features dual-mode architecture with intentionally vulnerable (Red Team) and secure (Blue Team) implementations.

---

## 🎯 Overview

SecureBank demonstrates **6 critical web security vulnerabilities** from the OWASP Top 10 and their proper fixes in a realistic banking application context. Each vulnerability is educational, exploitable, and comes with detailed explanations that help security learners understand both attack and defense.

### Why Banking?

Banking applications are prime targets for cybercriminals because they handle sensitive financial data and transactions. By learning security in a banking context, you'll understand:

- How attackers think when targeting financial systems
- The real-world impact of vulnerabilities (money loss, data breaches)
- Industry-standard security controls used by real banks
- Regulatory compliance requirements (PCI-DSS, GDPR, etc.)

### Key Features

- ✅ **Dual-Mode Architecture**: Red Team (vulnerable) and Blue Team (secure) versions
- ✅ **Professional Banking UI**: Modern, responsive design that looks like a real bank
- ✅ **Realistic Banking Features**: Account management, transfers, transactions, profiles, settings
- ✅ **Complete Code Examples**: Both vulnerable and secure implementations side-by-side
- ✅ **Educational Focus**: Detailed explanations of WHY vulnerabilities exist and HOW to fix them
- ✅ **Tool Integration**: Compatible with Burp Suite, SQLMap, OWASP ZAP, and Postman
- ✅ **Beginner to Advanced**: Suitable for complete beginners through security professionals

---

## 📊 Vulnerabilities Demonstrated

SecureBank teaches 6 critical vulnerabilities that affect real banking applications:

| # | Vulnerability | OWASP Category | Location | Severity | Real-World Impact |
|---|--------------|----------------|----------|----------|-------------------|
| 1 | **SQL Injection** | A03:2021 Injection | Login page | Critical | Complete database compromise |
| 2 | **IDOR** (Insecure Direct Object References) | A01:2021 Broken Access Control | Account access | High | Access to any user's account |
| 3 | **Race Condition** | A04:2021 Insecure Design | Money transfer | High | Unlimited money withdrawal |
| 4 | **XSS** (Cross-Site Scripting) | A03:2021 Injection | Transaction notes | High | Session hijacking, credential theft |
| 5 | **Mass Assignment** | A08:2023 Software Data Integrity | Profile update | Medium | Privilege escalation to admin |
| 6 | **CSRF** (Cross-Site Request Forgery) | - | Settings page | Medium | Unauthorized actions as victim |

Each vulnerability has been carefully chosen because it:
- Appears frequently in real-world applications
- Has caused actual security breaches
- Can be demonstrated clearly in a banking context
- Has a clear, industry-standard fix

---

## 🏗️ Architecture

```
SecureBank/
├── backend/apps/securebank/
│   ├── models.py                    # SQLAlchemy database models
│   ├── database.py                  # Database initialization
│   ├── seed_data.py                 # Realistic sample data
│   ├── securebank_red_api.py        # Red Team API (vulnerable)
│   └── securebank_blue_api.py       # Blue Team API (secure)
│
├── frontend/apps/securebank/
│   ├── red/                         # Red Team (Vulnerable)
│   │   ├── login.html               # SQL Injection demo
│   │   ├── dashboard.html           # Main dashboard
│   │   ├── accounts.html            # IDOR demo
│   │   ├── transfer.html            # Race condition demo
│   │   ├── transactions.html        # XSS demo
│   │   ├── profile.html             # Mass assignment demo
│   │   ├── settings.html            # CSRF demo
│   │   ├── css/                     # Professional styling
│   │   │   ├── banking.css          # Main banking styles
│   │   │   ├── responsive.css       # Mobile responsive
│   │   │   └── components.css       # Reusable UI components
│   │   └── js/                      # JavaScript modules
│   │       ├── utils.js             # Utility functions
│   │       └── auth.js              # Authentication logic
│   │
│   └── blue/                        # Blue Team (Secure)
│       └── [Same structure with security fixes]
│
└── docs/apps/securebank/
    ├── 00_README.md                 # This file - Overview
    ├── 01_SETUP_GUIDE.md            # Installation & setup instructions
    ├── 02_USER_GUIDE.md             # How to use the application
    ├── 03_ARCHITECTURE.md           # Technical architecture details
    ├── 04_SQL_INJECTION.md          # SQL Injection deep dive
    ├── 05_IDOR.md                   # IDOR vulnerability guide
    ├── 06_RACE_CONDITION.md         # Race condition guide
    ├── 07_XSS.md                    # XSS vulnerability guide
    ├── 08_MASS_ASSIGNMENT.md        # Mass assignment guide
    ├── 09_CSRF.md                   # CSRF vulnerability guide
    ├── 10_TESTING_WITH_POSTMAN.md   # Postman testing guide
    ├── 11_TESTING_WITH_BURP.md      # Burp Suite integration
    ├── 12_TESTING_WITH_SQLMAP.md    # Automated SQL injection testing
    ├── 13_TESTING_WITH_ZAP.md       # OWASP ZAP scanning
    ├── 14_REAL_WORLD_EXAMPLES.md    # Bug bounty case studies
    ├── 15_REMEDIATION_GUIDE.md      # How to fix vulnerabilities
    └── 16_TROUBLESHOOTING.md        # Common issues & solutions
```

---

## 🚀 Quick Start

### 1. Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Basic understanding of web applications
- Optional: Burp Suite, Postman, SQLMap, OWASP ZAP for testing

### 2. Installation

```bash
# Clone the repository
git clone https://github.com/your-org/aegisforgee.git
cd aegisforgee

# Install dependencies
pip install -r requirements.txt

# Initialize the database
cd backend/apps/securebank
python database.py
python seed_data.py
```

### 3. Running the Application

**Red Team (Vulnerable) Version:**
```bash
cd backend/apps/securebank
python securebank_red_api.py
```
Access at: http://localhost:5000/api/red/securebank

**Blue Team (Secure) Version:**
```bash
cd backend/apps/securebank
python securebank_blue_api.py
```
Access at: http://localhost:5001/api/blue/securebank

### 4. Test Credentials

The application comes with pre-seeded test accounts:

| Username | Password | Role | Account Balance |
|----------|----------|------|-----------------|
| admin | admin123 | Admin | $175,000.50 |
| john_doe | Password123! | Customer | $60,679.15 |
| sarah_miller | SecurePass456 | Customer | $8,532.40 |
| mike_wilson | Welcome2024 | Customer | $22,450.75 |

### 5. First Steps

1. Open `frontend/apps/securebank/red/login.html` in your browser
2. Login with any test account above
3. Explore the banking features (accounts, transfers, transactions)
4. Try the SQL injection attack: username = `admin' OR '1'='1'--`
5. Read the vulnerability guides to understand what's happening

---

## 📚 Documentation Structure

Our documentation follows a logical learning path:

### Getting Started (Docs 00-03)
- **00_README** (this file): Overview and quick start
- **01_SETUP_GUIDE**: Detailed installation and configuration
- **02_USER_GUIDE**: How to use SecureBank as a regular user
- **03_ARCHITECTURE**: Technical details for developers

### Vulnerability Deep Dives (Docs 04-09)
Each vulnerability guide follows the same structure:
1. **What** is the vulnerability?
2. **Why** does it exist in this code?
3. **How** to exploit it (step-by-step)
4. **Impact** in real-world scenarios
5. **How** to fix it properly
6. **Real examples** from bug bounties

- **04_SQL_INJECTION**: Authentication bypass and data exfiltration
- **05_IDOR**: Unauthorized access to other users' accounts
- **06_RACE_CONDITION**: Money duplication through timing attacks
- **07_XSS**: Injecting malicious scripts into the application
- **08_MASS_ASSIGNMENT**: Privilege escalation through parameter pollution
- **09_CSRF**: Forcing users to perform unwanted actions

### Testing Tools (Docs 10-13)
Learn how to use professional security testing tools:
- **10_TESTING_WITH_POSTMAN**: API testing and automation
- **11_TESTING_WITH_BURP**: Intercepting and modifying requests
- **12_TESTING_WITH_SQLMAP**: Automated SQL injection exploitation
- **13_TESTING_WITH_ZAP**: Automated vulnerability scanning

### Advanced Topics (Docs 14-16)
- **14_REAL_WORLD_EXAMPLES**: Bug bounty reports and CVEs
- **15_REMEDIATION_GUIDE**: Comprehensive fixing strategies
- **16_TROUBLESHOOTING**: Solutions to common problems

---

## 🎓 Learning Path

### For Complete Beginners

1. Read this README to understand the project
2. Follow **01_SETUP_GUIDE** to get everything running
3. Read **02_USER_GUIDE** to learn the banking features
4. Start with **04_SQL_INJECTION** (easiest to understand)
5. Try the exploit yourself using **10_TESTING_WITH_POSTMAN**
6. Compare Red vs Blue Team code to see the fix
7. Move on to other vulnerabilities in order (05, 06, 07, etc.)

### For Intermediate Users

1. Quick setup with **01_SETUP_GUIDE**
2. Jump straight to vulnerability guides (04-09)
3. Practice exploitation with tools (10-13)
4. Study **14_REAL_WORLD_EXAMPLES** for context
5. Read **15_REMEDIATION_GUIDE** for defense strategies

### For Advanced Users

1. Review **03_ARCHITECTURE** for technical details
2. Examine both Red and Blue Team source code
3. Use tools (11-13) to create automated test suites
4. Study **14_REAL_WORLD_EXAMPLES** for real CVEs
5. Contribute improvements or additional vulnerabilities

---

## 🔐 Security Notes

### Red Team API ⚠️

The Red Team version (`securebank_red_api.py`) contains **intentional security vulnerabilities** for educational purposes. 

**NEVER EVER** use this code in production. It includes:
- SQL injection vulnerabilities
- No authorization checks
- Race conditions
- XSS vulnerabilities
- Mass assignment flaws
- No CSRF protection
- Debug mode enabled
- Weak secret keys
- Exposed error messages

### Blue Team API ✅

The Blue Team version (`securebank_blue_api.py`) implements industry-standard security practices:
- Parameterized SQL queries
- Proper authorization checks
- Database transaction locking
- Output encoding
- Field whitelisting
- CSRF token validation
- Secure session management
- Rate limiting
- Security headers
- Proper error handling

Use the Blue Team code as a reference for secure coding practices.

---

## 🎯 Learning Objectives

After completing SecureBank, you will be able to:

### Knowledge
- ✅ Explain the 6 vulnerabilities in detail
- ✅ Understand the OWASP Top 10
- ✅ Recognize vulnerable code patterns
- ✅ Describe real-world attack scenarios
- ✅ Know industry-standard defenses

### Skills
- ✅ Identify vulnerabilities in web applications
- ✅ Exploit vulnerabilities ethically for testing
- ✅ Use professional security testing tools
- ✅ Write secure code that prevents these vulnerabilities
- ✅ Perform security code reviews
- ✅ Document security findings professionally

### Application
- ✅ Test web applications for security flaws
- ✅ Fix vulnerabilities in existing code
- ✅ Participate in bug bounty programs
- ✅ Contribute to secure development practices
- ✅ Educate others about web security

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

- **Report bugs**: Found something broken? Open an issue
- **Suggest improvements**: Have ideas? We'd love to hear them
- **Add vulnerabilities**: Know other common flaws? Add them
- **Improve documentation**: Make it clearer for beginners
- **Create tutorials**: Video walkthroughs, blog posts, etc.
- **Translate**: Help non-English speakers learn

---

## 📄 License

This project is part of AegisForge and is released under the MIT License. See LICENSE file for details.

---

## 🙏 Acknowledgments

SecureBank was built for education by security professionals who believe in:
- Open source security education
- Hands-on learning over theory
- Real-world context over academic examples
- Teaching WHY, not just HOW
- Making security accessible to everyone

---

## 📞 Support

Need help? Have questions?

- 📖 Read the documentation (you're here!)
- 🐛 Open an issue on GitHub
- 💬 Join our community discussions
- 📧 Contact the maintainers

---

## 🗺️ What's Next?

Ready to start learning? Here's what to do:

1. ➡️ **Next**: Read [01_SETUP_GUIDE.md](01_SETUP_GUIDE.md) to install SecureBank
2. Then: [02_USER_GUIDE.md](02_USER_GUIDE.md) to learn the features
3. Finally: Start with [04_SQL_INJECTION.md](04_SQL_INJECTION.md) for your first vulnerability

---

**Welcome to SecureBank! Let's make the web more secure together.** 🏦🔒
