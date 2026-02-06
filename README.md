# 🛡️ AegisForge - Complete Security Testing Platform

> **The most comprehensive dual-mode security learning platform for OWASP vulnerabilities**

AegisForge is a professional-grade security testing and education platform featuring dual-mode architecture (Red Team vulnerable endpoints + Blue Team secure implementations) with complete OWASP coverage, CTF challenges, ML-based threat detection, and integrated security analytics.

[![Version](https://img.shields.io/badge/version-2.0-blue.svg)](https://github.com/balasunil-8/aegisforgee)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Web%202021-red.svg)](https://owasp.org/www-project-top-ten/)
[![OWASP](https://img.shields.io/badge/OWASP-API%202023-red.svg)](https://owasp.org/www-project-api-security/)

---

## 📚 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Dual-Mode Operation](#-dual-mode-operation)
- [Tool Integration](#-tool-integration)
- [CTF Challenges](#-ctf-challenges)
- [Security Analytics](#-security-analytics)
- [Documentation](#-documentation)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)

---

## ✨ Features

### 🎯 Dual-Mode Architecture
- **Red Team Mode**: 40+ intentionally vulnerable endpoints covering all OWASP categories
- **Blue Team Mode**: 52+ hardened secure implementations with defense-in-depth
- **Comparison Mode**: Side-by-side testing of vulnerable vs secure code

### 🔒 Complete OWASP Coverage
- **OWASP Web Top 10 2021**: 100% coverage
- **OWASP API Top 10 2023**: 100% coverage
- Real-world vulnerability examples with exploitation paths

### 🧩 Defense Module Library
- **Input Validation**: SQL, XSS, command injection, path traversal protection
- **Security Headers**: CSP, HSTS, X-Frame-Options, CSRF tokens
- **Rate Limiting**: Configurable IP-based and user-based limits
- **Access Control**: RBAC, object-level authorization, ownership validation

### 🎮 CTF Challenge System
- **18 Progressive Challenges**: 100-300 points each (2,700 total points)
- **Real-Time Leaderboard**: Competitive scoring with timestamps
- **Difficulty Levels**: Easy, Medium, Hard
- **Categories**: SQLi, XSS, Access Control, Authentication, Injection, SSRF, Business Logic

### 🤖 ML-Based Threat Detection
- **Enhanced AI Detector**: Ensemble Random Forest + Gradient Boosting
- **Explainable AI**: Feature importance and attack type classification
- **Remediation Suggestions**: Actionable security recommendations
- **Rule-Based Fallback**: Works without training data

### 📊 Security Analytics Dashboard
- **Real-Time Monitoring**: Attack logs, trends, and statistics
- **Threat Intelligence**: Risk assessment and attack patterns
- **Endpoint Analytics**: Per-endpoint attack rates and types
- **User Analytics**: Track security events per user
- **Timeline Visualization**: Hourly/daily attack breakdowns

### 🔧 Professional Tool Integration
- **Postman**: 141+ pre-built requests with automated tests
- **Burp Suite**: Project configuration + 380 intruder payloads
- **OWASP ZAP**: Automation framework with full scan policies
- **SQLMap**: Executable test suite for all SQLi endpoints
- **FFUF**: Fuzzing scripts with auto-generated wordlists

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AegisForge Platform                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐         ┌──────────────────┐                │
│  │   Red Team API   │         │  Blue Team API   │                │
│  │  Port: 5000      │         │  Port: 5001      │                │
│  │  40+ Vulnerable  │         │  52+ Secure      │                │
│  │  Endpoints       │         │  Endpoints       │                │
│  └────────┬─────────┘         └────────┬─────────┘                │
│           │                            │                           │
│           └────────────┬───────────────┘                           │
│                        │                                           │
│           ┌────────────▼──────────────┐                           │
│           │  Dual-Mode Controller     │                           │
│           │  (aegisforge_modes.py)    │                           │
│           └────────────┬──────────────┘                           │
│                        │                                           │
│        ┌───────────────┼───────────────────┐                      │
│        │               │                   │                      │
│  ┌─────▼────┐   ┌─────▼──────┐   ┌───────▼──────┐               │
│  │ Defense  │   │ Analytics  │   │ CTF System   │               │
│  │ Modules  │   │ Dashboard  │   │ Leaderboard  │               │
│  │ 4 Libs   │   │ Port: 5003 │   │ Port: 5002   │               │
│  └──────────┘   └────────────┘   └──────────────┘               │
│                                                                    │
│  ┌────────────────────────────────────────────────────┐          │
│  │              ML Threat Detector                     │          │
│  │  Random Forest + Gradient Boosting Ensemble        │          │
│  │  Feature Extraction • Attack Classification        │          │
│  └────────────────────────────────────────────────────┘          │
│                                                                    │
│  ┌────────────────────────────────────────────────────┐          │
│  │              Tool Integration Layer                 │          │
│  │  Postman • Burp • ZAP • SQLMap • FFUF              │          │
│  └────────────────────────────────────────────────────┘          │
│                                                                    │
└─────────────────────────────────────────────────────────────────────┘
```

### Component Breakdown

| Component | Port | Purpose | Files |
|-----------|------|---------|-------|
| Red Team API | 5000 | Vulnerable endpoints | `aegisforge_api.py` |
| Blue Team API | 5001 | Secure implementations | `aegisforge_blue.py` |
| CTF Leaderboard | 5002 | Challenge system | `aegisforge_leaderboard.py` |
| Analytics Dashboard | 5003 | Security monitoring | `aegisforge_analytics.py` |
| Dual-Mode Controller | - | Service orchestration | `aegisforge_modes.py` |
| Defense Library | - | Security utilities | `defenses/*.py` |
| AI Detector | - | Threat detection | `ai/enhanced_detector.py` |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip package manager
- (Optional) Docker for containerized deployment

### Installation

```bash
# Clone the repository
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Linux/Mac:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python init_db.py
```

### Running AegisForge

#### Option 1: Interactive Mode (Recommended)

```bash
python aegisforge_modes.py
```

This launches an interactive menu where you can:
1. Start Red Team API (vulnerable)
2. Start Blue Team API (secure)
3. Start Comparison Mode (both)
4. Stop all services
5. Show status

#### Option 2: Command Line Mode

```bash
# Start Red Team only
python aegisforge_modes.py red

# Start Blue Team only
python aegisforge_modes.py blue

# Start both for comparison
python aegisforge_modes.py compare

# Check status
python aegisforge_modes.py status
```

#### Option 3: Individual Services

```bash
# Red Team API (Port 5000)
python aegisforge_api.py

# Blue Team API (Port 5001)
python aegisforge_blue.py

# CTF Leaderboard (Port 5002)
python aegisforge_leaderboard.py

# Analytics Dashboard (Port 5003)
python aegisforge_analytics.py
```

### Docker Deployment

```bash
# Build image
docker build -t aegisforge:latest .

# Run Red Team
docker run -p 5000:5000 aegisforge:latest python aegisforge_api.py

# Run Blue Team
docker run -p 5001:5001 aegisforge:latest python aegisforge_blue.py

# Run with docker-compose (all services)
docker-compose up
```

---

## 🔄 Dual-Mode Operation

AegisForge's unique dual-mode architecture allows side-by-side comparison of vulnerable and secure implementations.

### Red Team Mode (Port 5000)

**Purpose**: Learn exploitation techniques
- Intentionally vulnerable endpoints
- No input validation
- Insecure coding practices
- Verbose error messages
- Educational attack examples

```bash
# Example: SQL Injection
curl "http://localhost:5000/api/injection/sqli/boolean?username=' OR '1'='1"

# Example: XSS
curl "http://localhost:5000/api/xss/reflected?message=<script>alert('XSS')</script>"
```

### Blue Team Mode (Port 5001)

**Purpose**: Learn secure coding practices
- Hardened implementations
- Input validation and sanitization
- Defense-in-depth layers
- Security headers
- Parameterized queries

```bash
# Example: SQL Injection Protection
curl "http://localhost:5001/api/blue/injection/sqli/boolean?username=' OR '1'='1"
# Returns: 400 Bad Request - Invalid input detected

# Example: XSS Protection
curl "http://localhost:5001/api/blue/xss/reflected?message=<script>alert('XSS')</script>"
# Returns: HTML-encoded output, CSP headers
```

### Comparison Mode

Run both APIs simultaneously to compare responses:

```bash
# Start comparison mode
python aegisforge_modes.py compare

# Test vulnerable endpoint
curl http://localhost:5000/api/injection/sqli/boolean?username=admin

# Test secure endpoint
curl http://localhost:5001/api/blue/injection/sqli/boolean?username=admin
```

---

## 🔧 Tool Integration

AegisForge provides ready-to-use configurations for professional security testing tools.

### Postman Collection

Located in `postman/`:
- **141+ Requests**: Complete coverage of all endpoints
- **Automated Tests**: Pre/post-request scripts
- **Environment Variables**: Auto-populated tokens and IDs
- **Documentation**: Inline descriptions and examples

```bash
# Import collection
File → Import → postman/AegisForge_Complete_Collection.json

# Run with Newman (CLI)
newman run postman/AegisForge_Complete_Collection.json
```

### Burp Suite

Located in `burp/`:
- **Project Configuration**: Pre-configured scope and settings
- **Intruder Payloads**: 380+ attack payloads
  - SQL Injection (120 payloads)
  - XSS (150 payloads)
  - Command Injection (60 payloads)
  - Path Traversal (50 payloads)

### OWASP ZAP

Located in `zap/`:
- **Automation Framework**: Full scan configuration
- **Custom Rules**: AegisForge-specific detection
- **CI/CD Integration**: GitHub Actions ready

```bash
# Run automated scan
zap-cli --api-key YOUR_KEY scan http://localhost:5000 \
  --config-file zap/automation_scan.yaml
```

### SQLMap

Located in `sqlmap/`:
- **20+ Automated Tests**: All SQL injection endpoints
- **Tamper Scripts**: WAF bypass techniques
- **Batch Execution**: Test all endpoints at once

```bash
# Run all SQLMap tests
cd sqlmap
chmod +x aegisforge_tests.sh
./aegisforge_tests.sh
```

### FFUF

Located in `ffuf/`:
- **Endpoint Discovery**: Find hidden endpoints
- **Parameter Fuzzing**: Test all input vectors
- **Auto-Generated Wordlists**: Custom payloads for AegisForge

```bash
# Run fuzzing suite
cd ffuf
chmod +x aegisforge_fuzzing.sh
./aegisforge_fuzzing.sh
```

---

## 🎮 CTF Challenges

AegisForge includes 18 progressive CTF challenges across all difficulty levels.

### Challenge Categories

| Category | Challenges | Total Points | Difficulty Range |
|----------|------------|--------------|------------------|
| SQL Injection | 3 | 450 | Easy - Medium |
| XSS | 2 | 250 | Easy - Medium |
| Access Control | 3 | 500 | Easy - Medium |
| Authentication | 2 | 250 | Easy - Medium |
| Injection (Other) | 2 | 450 | Medium - Hard |
| SSRF | 1 | 200 | Medium |
| Deserialization | 1 | 300 | Hard |
| Business Logic | 2 | 400 | Medium - Hard |
| Info Disclosure | 1 | 100 | Easy |
| CSRF | 1 | 150 | Medium |

### Using the CTF System

```bash
# Start CTF leaderboard
python aegisforge_leaderboard.py

# View challenges
curl http://localhost:5002/api/ctf/challenges

# Submit flag
curl -X POST http://localhost:5002/api/ctf/submit \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_username",
    "challenge_id": "sqli-001",
    "flag": "AEGIS{your_flag_here}"
  }'

# View leaderboard
curl http://localhost:5002/api/ctf/leaderboard
```

### Flag Format

All flags follow the format: `AEGIS{flag_content_here}`

Example: `AEGIS{b00l34n_sql1_m4st3r}`

---

## 📊 Security Analytics

Real-time security monitoring and threat intelligence.

### Starting Analytics Dashboard

```bash
python aegisforge_analytics.py
# Accessible at http://localhost:5003
```

### Available Analytics

#### Attack Summary
```bash
curl http://localhost:5003/api/analytics/summary?hours=24
```
Returns:
- Total attacks in period
- Attack types breakdown
- Block rate percentage
- Hourly breakdown
- Peak attack times

#### Endpoint Analytics
```bash
curl http://localhost:5003/api/analytics/endpoints
```
Returns per-endpoint:
- Total requests
- Attack rate percentage
- Attack types

#### Threat Intelligence
```bash
curl http://localhost:5003/api/analytics/threat-intelligence
# 🛡️ AegisForge - Ultimate Security Learning Platform

**Master Offensive & Defensive Security**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Flask](https://img.shields.io/badge/Flask-3.0.2-green.svg)](https://flask.palletsprojects.com/)

---

## 🎯 What is AegisForge?

Professional-grade security testing platform for **Red Team (offensive)** and **Blue Team (defensive)** training.

### ✨ Key Features

- ✅ **Dual-Mode Learning**: Toggle between vulnerable and hardened endpoints
- ✅ **Complete OWASP Coverage**: Web 2021/2025 + API 2023
- ✅ **CTF Arena**: 5 real-world challenges (100-300pts)
- ✅ **AI Detection**: ML-based attack classification
- ✅ **Tool Integration**: Postman, Burp, SQLMap, ZAP, FFUF
- ✅ **Cloud Ready**: Railway, Render, Docker

---

## 🚀 Quick Start

```bash
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python aegisforge_api.py
```

Visit: `http://localhost:5000`

---

## 🎮 Dual-Mode System

### 🔴 Red Team (Offensive)
```bash
curl -X POST http://localhost:5000/api/mode/set -H "Content-Type: application/json" -d '{"mode":"red"}'
```

### 🔵 Blue Team (Defensive)
```bash
curl -X POST http://localhost:5000/api/mode/set -H "Content-Type: application/json" -d '{"mode":"blue"}'
```
Returns:
- Attack trends
- Risk assessment
- Top attack patterns
- Security recommendations

---

## 📖 Documentation

Comprehensive documentation is provided for all aspects of AegisForge:

| Document | Description |
|----------|-------------|
| [README.md](README.md) | This file - overview and quick start |
| [SECURITY_COMPARISON.md](SECURITY_COMPARISON.md) | Side-by-side Red vs Blue comparisons |
| [API_DOCUMENTATION.md](API_DOCUMENTATION.md) | Complete API reference |
| [TOOL_INTEGRATION_README.md](TOOL_INTEGRATION_README.md) | Testing tools setup guide |
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | Production deployment instructions |
| [postman/README.md](postman/README.md) | Postman collection guide |

---

## 📁 Project Structure

```
aegisforgee/
├── aegisforge_api.py              # Red Team vulnerable endpoints
├── aegisforge_blue.py             # Blue Team secure endpoints
├── aegisforge_modes.py            # Dual-mode orchestration
├── aegisforge_leaderboard.py      # CTF challenge system
├── aegisforge_analytics.py        # Security analytics dashboard
│
├── defenses/                      # Defense module library
│   ├── __init__.py
│   ├── input_validator.py         # Input validation utilities
│   ├── security_headers.py        # Security header management
│   ├── rate_limiter.py            # Rate limiting implementation
│   └── access_control.py          # Authorization utilities
│
├── ai/                            # ML-based threat detection
│   ├── __init__.py
│   └── enhanced_detector.py       # Enhanced AI detector
│
├── postman/                       # Postman collection
│   ├── AegisForge_Complete_Collection.json
│   ├── QUICK_START.md
│   └── README.md
│
├── burp/                          # Burp Suite configuration
│   ├── AegisForge_Project.json
│   └── AegisForge_Intruder_Payloads.txt
│
├── zap/                           # OWASP ZAP automation
│   └── automation_scan.yaml
│
├── sqlmap/                        # SQLMap test scripts
│   └── aegisforge_tests.sh
│
├── ffuf/                          # FFUF fuzzing scripts
│   └── aegisforge_fuzzing.sh
│
├── ctf_challenges/                # CTF challenge files
│   └── [challenge directories]
│
├── models/                        # ML model storage
│
├── docs/                          # Additional documentation
│
├── requirements.txt               # Python dependencies
├── docker-compose.yml             # Docker orchestration
├── Dockerfile                     # Container definition
└── README.md                      # This file
```

---

## 🎓 Learning Path

Recommended learning progression:

### Beginner (Week 1-2)
1. Start with Red Team mode
2. Complete Easy CTF challenges (SQL Injection, XSS, IDOR)
3. Use Postman collection for guided exploration
4. Review SECURITY_COMPARISON.md for each vulnerability

### Intermediate (Week 3-4)
1. Switch to Comparison mode
2. Complete Medium CTF challenges
3. Use Burp Suite for manual exploitation
4. Study Blue Team implementations
5. Implement your own fixes

### Advanced (Week 5-6)
1. Complete Hard CTF challenges
2. Use SQLMap and FFUF for advanced exploitation
3. Analyze ML detector results
4. Review analytics dashboard insights
5. Contribute to defense modules

---

## 🔬 Testing Examples

### SQL Injection Testing

```bash
# Red Team - Vulnerable
curl "http://localhost:5000/api/injection/sqli/boolean?username=' OR '1'='1"
# ❌ Returns all users

# Blue Team - Secure
curl "http://localhost:5001/api/blue/injection/sqli/boolean?username=' OR '1'='1"
# ✅ Returns 400 - Invalid input detected
```

### XSS Testing

```bash
# Red Team - Vulnerable
curl "http://localhost:5000/api/xss/reflected?message=<script>alert(1)</script>"
# ❌ Script executes

# Blue Team - Secure
curl "http://localhost:5001/api/blue/xss/reflected?message=<script>alert(1)</script>"
# ✅ HTML encoded output + CSP headers
```

### IDOR Testing

```bash
# Red Team - Vulnerable
curl "http://localhost:5000/api/access/idor/1"
# ❌ Returns admin data without authentication

# Blue Team - Secure
curl "http://localhost:5001/api/blue/access/idor/1"
# ✅ Returns 401 - Authentication required
```

---

## 🛠️ Development

### Adding New Vulnerabilities

1. Add vulnerable endpoint to `aegisforge_api.py`
2. Add secure counterpart to `aegisforge_blue.py`
3. Update `SECURITY_COMPARISON.md` with comparison
4. Add Postman requests for both endpoints
5. Create CTF challenge if appropriate

### Adding New Defense Modules

1. Create module in `defenses/` directory
2. Import in relevant API files
3. Add unit tests
4. Update documentation

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas for contribution:
- New vulnerability examples
- Defense module improvements
- CTF challenges
- Documentation enhancements
- Tool integrations
- ML model improvements

---

## ⚠️ Security Warning

**IMPORTANT**: AegisForge contains intentionally vulnerable code for educational purposes.

### DO NOT:
- Deploy Red Team mode to production
- Expose AegisForge to the public internet without proper isolation
- Use in production environments
- Use on systems containing real user data

### DO:
- Use in isolated lab environments
- Use for security training and education
- Use for penetration testing practice
- Contribute improvements and new features

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- OWASP Foundation for security standards
- Security research community
- Contributors and users

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/balasunil-8/aegisforgee/issues)
- **Discussions**: [GitHub Discussions](https://github.com/balasunil-8/aegisforgee/discussions)
- **Documentation**: See `/docs` directory

---

## 🗺️ Roadmap

### Version 2.1 (Planned)
- [ ] GraphQL vulnerability examples
- [ ] WebSocket security testing
- [ ] JWT exploitation scenarios
- [ ] Advanced SSRF techniques
- [ ] Mobile API security patterns

### Version 3.0 (Future)
- [ ] Web UI for analytics dashboard
- [ ] Automated exploit generation
- [ ] Integration with SIEM systems
- [ ] Advanced ML models (Deep Learning)
- [ ] Multi-language support

---

**Built with ❤️ for the security community**

*AegisForge v2.0 - Complete Security Testing Platform*
## 📖 Vulnerabilities

50+ vulnerabilities including:
- SQL Injection (Boolean, Time, UNION)
- XSS (Reflected, Stored, DOM)
- IDOR, BFLA, Mass Assignment
- SSRF, Command Injection, XXE
- Deserialization, Race Conditions
- Authentication & Access Control flaws

---

## 🏆 CTF Challenges

1. **AREA64** (100pts) - Base64 crypto
2. **SmallE** (100pts) - RSA attack  
3. **Hidden Layers** (100pts) - Steganography
4. **Paper Script** (300pts) - PDF forensics
5. **Synthetic Stacks** (300pts) - Multi-layer

---

## 🔧 Tools

- **Postman**: Import collection
- **Burp Suite**: Configure proxy
- **SQLMap**: `sqlmap -u "http://localhost:5000/api/injection/sqli/boolean?username=test"`
- **ZAP**: `zap-cli quick-scan http://localhost:5000`
- **FFUF**: `ffuf -u http://localhost:5000/FUZZ -w wordlist.txt`

---

## ⚠️ Legal Notice

**Educational use only** in isolated environments. Never test systems without authorization.

---

## 📚 Documentation

See: `POSTMAN_GUIDE.md`, `BURP_SUITE_GUIDE.md`, `SQLMAP_GUIDE.md`, `OWASP_ZAP_GUIDE.md`, `FFUF_GUIDE.md`

---

**Happy Ethical Hacking! 🛡️**
