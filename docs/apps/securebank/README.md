# 🏦 SecureBank - Interactive Banking Web Application

**Part of the AegisForge Security Education Platform**

SecureBank is a complete, professional banking web application designed to teach web security vulnerabilities and their defenses through hands-on practice. It features dual-mode architecture with intentionally vulnerable (Red Team) and secure (Blue Team) implementations.

---

## 🎯 Overview

SecureBank demonstrates **6 critical web security vulnerabilities** from the OWASP Top 10 and their proper fixes in a realistic banking application context. Each vulnerability is educational, exploitable, and comes with detailed explanations.

### Key Features

- ✅ **Dual-Mode Architecture**: Red Team (vulnerable) and Blue Team (secure) versions
- ✅ **Professional Banking UI**: Modern, responsive design with mobile support
- ✅ **Realistic Banking Features**: Accounts, transfers, transactions, profiles, settings
- ✅ **Complete Code Examples**: Both vulnerable and secure implementations
- ✅ **Educational Focus**: Detailed explanations, exploitation guides, and defense strategies
- ✅ **Tool Integration**: Works with Burp Suite, SQLMap, OWASP ZAP, and Postman

---

## 📊 Vulnerabilities Demonstrated

| # | Vulnerability | OWASP | Location | Severity |
|---|--------------|-------|----------|----------|
| 1 | **SQL Injection** | A03:2021 | Login page | Critical |
| 2 | **IDOR** (Insecure Direct Object References) | A01:2021 | Account access | High |
| 3 | **Race Condition** | A04:2021 | Money transfer | High |
| 4 | **XSS** (Cross-Site Scripting) | A03:2021 | Transaction notes | High |
| 5 | **Mass Assignment** | A08:2023 | Profile update | Medium |
| 6 | **CSRF** (Cross-Site Request Forgery) | - | Settings page | Medium |

---

## 🏗️ Architecture

```
SecureBank/
├── backend/apps/securebank/
│   ├── models.py                    # Database models (SQLAlchemy)
│   ├── database.py                  # DB initialization
│   ├── seed_data.py                 # Sample data
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
│   │   │   ├── banking.css          # Main styles
│   │   │   ├── responsive.css       # Mobile responsive
│   │   │   └── components.css       # Reusable components
│   │   └── js/                      # JavaScript modules
│   │       ├── utils.js             # Utility functions
│   │       └── auth.js              # Authentication logic
│   │
│   └── blue/                        # Blue Team (Secure)
│       └── [Same structure with security fixes]
│
└── docs/apps/securebank/
    ├── README.md                    # This file
    ├── SETUP_GUIDE.md               # Installation instructions
    ├── USER_GUIDE.md                # How to use
    ├── VULNERABILITY_GUIDE.md       # Detailed vulnerability explanations
    ├── EXPLOITATION_GUIDE.md        # Step-by-step exploitation
    ├── DEFENSE_GUIDE.md             # Security mechanisms
    ├── TESTING_WITH_POSTMAN.md      # Postman testing guide
    ├── TESTING_WITH_BURP.md         # Burp Suite guide
    ├── TESTING_WITH_SQLMAP.md       # SQLMap guide
    ├── TESTING_WITH_ZAP.md          # OWASP ZAP guide
    ├── REAL_WORLD_EXAMPLES.md       # Bug bounty case studies
    └── TROUBLESHOOTING.md           # Common issues & solutions
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Flask and dependencies (see requirements.txt)
- Modern web browser
- (Optional) Security testing tools

### 1. Initialize Database

```bash
cd backend/apps/securebank
python seed_data.py
```

This creates a SQLite database with sample users, accounts, and transactions.

### 2. Start Red Team API (Vulnerable)

```bash
python securebank_red_api.py
```

Runs on: http://localhost:5000

### 3. Start Blue Team API (Secure)

```bash
# In a separate terminal
python securebank_blue_api.py
```

Runs on: http://localhost:5001

### 4. Open Frontend

**Red Team (Vulnerable):**
```
frontend/apps/securebank/red/login.html
```

**Blue Team (Secure):**
```
frontend/apps/securebank/blue/login.html
```

### 5. Login with Test Credentials

| Username | Password | Role |
|----------|----------|------|
| alice | password123 | User |
| bob | securepass456 | User |
| admin | admin123 | Admin |
| carol | carol789 | User |

---

## 🎓 Educational Flow

### For Learners

1. **Start with Red Team**: Experience vulnerabilities firsthand
2. **Try Exploits**: Use provided test cases to exploit each vulnerability
3. **Understand Impact**: See what attackers can do
4. **Study Blue Team**: Compare secure implementation
5. **Learn Defenses**: Understand how each fix works
6. **Practice Tools**: Use Burp Suite, SQLMap, etc.
7. **Read Documentation**: Deep dive into each vulnerability

### For Instructors

1. Use as live demonstration in classes
2. Assign as hands-on lab exercises
3. Reference in security training programs
4. Use for CTF-style challenges
5. Demonstrate tool usage (Burp, ZAP, SQLMap)

---

## 🔴 Red Team Version (Vulnerable)

### Intentional Vulnerabilities

#### 1. SQL Injection (Login)
- **Location**: `securebank_red_api.py` - `/login` endpoint
- **Attack**: `username = admin' OR '1'='1'--`
- **Impact**: Authentication bypass, database access

#### 2. IDOR (Accounts)
- **Location**: `securebank_red_api.py` - `/account/<id>` endpoint
- **Attack**: Change account ID in URL (e.g., 1001 → 1002)
- **Impact**: Access other users' account information

#### 3. Race Condition (Transfer)
- **Location**: `securebank_red_api.py` - `/transfer` endpoint
- **Attack**: Send multiple concurrent transfer requests
- **Impact**: Overdraw account, create money from nothing

#### 4. XSS (Transactions)
- **Location**: `transactions.html` - Note rendering with `innerHTML`
- **Attack**: `<script>alert(document.cookie)</script>` in notes
- **Impact**: Session hijacking, credential theft, phishing

#### 5. Mass Assignment (Profile)
- **Location**: `securebank_red_api.py` - `/profile` PUT endpoint
- **Attack**: Add `{"role": "admin"}` to update request
- **Impact**: Privilege escalation, unauthorized access

#### 6. CSRF (Settings)
- **Location**: `securebank_red_api.py` - `/settings` POST endpoint
- **Attack**: Malicious page triggers form submission
- **Impact**: Unauthorized settings changes

---

## 🔵 Blue Team Version (Secure)

### Security Controls Implemented

#### 1. SQL Injection Prevention
- ✅ **Parameterized queries**: Uses `?` placeholders
- ✅ **Input validation**: Server-side validation
- ✅ **Error handling**: No database error leakage
- **Code**: `securebank_blue_api.py` - `/login`

#### 2. IDOR Prevention
- ✅ **Authorization checks**: Verifies ownership with `user_id`
- ✅ **Session validation**: Requires authentication
- ✅ **Indirect references**: Could use UUIDs instead of sequential IDs
- **Code**: `securebank_blue_api.py` - `/account/<id>`

#### 3. Race Condition Prevention
- ✅ **Database transactions**: `BEGIN EXCLUSIVE`
- ✅ **Mutex locks**: Threading lock wrapper
- ✅ **Atomic operations**: All-or-nothing updates
- **Code**: `securebank_blue_api.py` - `/transfer`

#### 4. XSS Prevention
- ✅ **Output encoding**: HTML entity encoding with `escapeHTML()`
- ✅ **Content Security Policy**: CSP headers
- ✅ **textContent over innerHTML**: Safe rendering
- **Code**: `transactions.html` (Blue Team) + `securebank_blue_api.py`

#### 5. Mass Assignment Prevention
- ✅ **Field whitelisting**: Only allowed fields accepted
- ✅ **Input validation**: Format and content validation
- ✅ **Explicit field mapping**: No dynamic field acceptance
- **Code**: `securebank_blue_api.py` - `/profile`

#### 6. CSRF Prevention
- ✅ **CSRF tokens**: Synchronizer token pattern
- ✅ **Token validation**: Server-side verification
- ✅ **Token rotation**: New token after state changes
- ✅ **SameSite cookies**: Additional protection layer
- **Code**: `securebank_blue_api.py` - `/settings`

---

## 🛠️ Technology Stack

- **Backend**: Python Flask, SQLite, SQLAlchemy
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Security**: CORS, Sessions, CSRF tokens, Input validation
- **Design**: Responsive, mobile-first, professional banking UI

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [SETUP_GUIDE.md](SETUP_GUIDE.md) | Detailed installation and setup instructions |
| [USER_GUIDE.md](USER_GUIDE.md) | How to use all features |
| [VULNERABILITY_GUIDE.md](VULNERABILITY_GUIDE.md) | In-depth vulnerability explanations |
| [EXPLOITATION_GUIDE.md](EXPLOITATION_GUIDE.md) | Step-by-step exploitation tutorials |
| [DEFENSE_GUIDE.md](DEFENSE_GUIDE.md) | Security mechanism deep dives |
| [TESTING_WITH_POSTMAN.md](TESTING_WITH_POSTMAN.md) | Postman testing guide |
| [TESTING_WITH_BURP.md](TESTING_WITH_BURP.md) | Burp Suite testing guide |
| [TESTING_WITH_SQLMAP.md](TESTING_WITH_SQLMAP.md) | SQLMap automation guide |
| [TESTING_WITH_ZAP.md](TESTING_WITH_ZAP.md) | OWASP ZAP scanning guide |
| [REAL_WORLD_EXAMPLES.md](REAL_WORLD_EXAMPLES.md) | Real bug bounty stories |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues and solutions |

---

## ⚠️ Security Warning

**Red Team Version**: Contains intentional security vulnerabilities for educational purposes. **NEVER** deploy to production or expose to the internet. Use only in controlled environments for learning.

**Blue Team Version**: While implementing security best practices, this is still an educational application. Additional hardening would be needed for real-world production use.

---

## 🎯 Learning Objectives

After using SecureBank, learners will be able to:

1. ✅ Identify and exploit SQL injection vulnerabilities
2. ✅ Understand and demonstrate IDOR attacks
3. ✅ Recognize race condition vulnerabilities
4. ✅ Execute XSS attacks and understand their impact
5. ✅ Exploit mass assignment vulnerabilities
6. ✅ Demonstrate CSRF attacks
7. ✅ Implement proper security controls for each vulnerability
8. ✅ Use security testing tools effectively
9. ✅ Write secure code following OWASP guidelines
10. ✅ Perform security code reviews

---

## 🤝 Contributing

SecureBank is part of the open-source AegisForge project. Contributions are welcome!

- Report bugs via GitHub Issues
- Suggest improvements
- Add new vulnerabilities or features
- Improve documentation
- Create tutorials or videos

---

## 📄 License

MIT License - See main AegisForge repository for details.

---

## 🙏 Credits

- **AegisForge Team**: Platform development
- **OWASP**: Vulnerability classifications and best practices
- **Security Community**: Real-world examples and insights

---

## 📞 Support

- **Documentation**: See docs/apps/securebank/
- **Issues**: GitHub Issues
- **Community**: AegisForge discussions
- **Email**: support@aegisforge.io

---

**Happy Learning! 🎓 Stay Secure! 🔒**
