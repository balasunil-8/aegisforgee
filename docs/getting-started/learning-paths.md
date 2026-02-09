# 🎓 Learning Paths

Structured learning paths for mastering web application security with AegisForge.

---

## 🗺️ Overview

AegisForge offers multiple learning paths based on your experience level and goals:

- **🌱 Beginner**: New to web security (2-3 weeks)
- **🔧 Intermediate**: Some security knowledge (2-3 weeks)
- **⚡ Advanced**: Experienced in security testing (1-2 weeks)
- **🎯 Certification Prep**: Preparing for certifications
- **👨‍💻 Developer Focus**: Secure coding practices

---

## 🌱 Beginner Path (Zero to Hero)

**Target Audience**: New to web application security
**Duration**: 2-3 weeks
**Goal**: Understand common vulnerabilities and basic exploitation

### Week 1: Foundation

#### Day 1-2: Platform Familiarization
- [ ] Complete installation and setup
- [ ] Understand dual-mode architecture (Red vs Blue Team)
- [ ] Register user account
- [ ] Test basic API endpoints
- [ ] Set up Postman

**Resources**:
- [first-time-setup.md](first-time-setup.md)
- [API_DOCUMENTATION.md](../../API_DOCUMENTATION.md)
- [POSTMAN_GUIDE.md](../../POSTMAN_GUIDE.md)

#### Day 3-4: SQL Injection
- [ ] Study SQL injection theory
- [ ] Test `/api/vulnerable/sqli` endpoint
- [ ] Try different SQL injection payloads
- [ ] Compare with `/api/secure/sqli`
- [ ] Complete CTF Challenge #1 (100 points)

**Payloads to Try**:
```sql
1 OR 1=1
1' OR '1'='1
1' UNION SELECT null, username, password FROM users--
```

**Resources**:
- OWASP SQL Injection Guide
- SQLMap tutorial in [SQLMAP_GUIDE.md](../../SQLMAP_GUIDE.md)

#### Day 5-7: Cross-Site Scripting (XSS)
- [ ] Learn about XSS types (Reflected, Stored, DOM)
- [ ] Test `/api/vulnerable/xss` endpoints
- [ ] Create custom XSS payloads
- [ ] Study output encoding in secure version
- [ ] Complete CTF Challenges #2-3 (200 points)

**Payloads to Try**:
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

### Week 2: Core Vulnerabilities

#### Day 8-9: Broken Access Control
- [ ] Understand IDOR (Insecure Direct Object Reference)
- [ ] Test BOLA (Broken Object Level Authorization)
- [ ] Test BFLA (Broken Function Level Authorization)
- [ ] Study access control patterns
- [ ] Complete CTF Challenge #4-5 (300 points)

**Test Scenarios**:
```bash
# BOLA - Access other user's data
GET /api/vulnerable/user/2/profile
# When logged in as user 1

# BFLA - Access admin functions
GET /api/vulnerable/admin/users
# As regular user
```

#### Day 10-11: Authentication & Session Management
- [ ] Test weak password policies
- [ ] Attempt brute force attacks (rate limiting)
- [ ] Study JWT token vulnerabilities
- [ ] Test session fixation
- [ ] Complete CTF Challenge #6 (150 points)

#### Day 12-14: CSRF and Security Headers
- [ ] Understand CSRF attacks
- [ ] Test CSRF vulnerabilities
- [ ] Study security headers (CSP, HSTS, X-Frame-Options)
- [ ] Complete CTF Challenges #7-8 (300 points)

### Week 3: Consolidation

#### Day 15-17: Tool Integration
- [ ] Set up OWASP ZAP
- [ ] Run automated scans
- [ ] Set up Burp Suite Community
- [ ] Intercept and modify requests
- [ ] Use SQLMap on vulnerable endpoints

#### Day 18-20: Practice & Review
- [ ] Review all completed challenges
- [ ] Attempt remaining beginner CTF challenges
- [ ] Study secure implementations
- [ ] Compare vulnerable vs secure code
- [ ] Take beginner assessment test

#### Day 21: Assessment
- [ ] Complete all Easy difficulty CTF challenges
- [ ] Score: 800+ points
- [ ] Write summary of learnings

---

## 🔧 Intermediate Path

**Target Audience**: Basic understanding of web security
**Duration**: 2-3 weeks
**Goal**: Master OWASP Top 10, advanced exploitation techniques

### Week 1: OWASP Deep Dive

#### Day 1-2: Injection Attacks (Advanced)
- [ ] Command injection exploitation
- [ ] LDAP injection
- [ ] XML injection
- [ ] Template injection
- [ ] Complete CTF Challenges #9-10 (400 points)

**Advanced Payloads**:
```bash
# Command injection
; ls -la
| cat /etc/passwd
$(whoami)

# Template injection (Python)
{{7*7}}
{{config}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

#### Day 3-5: XML External Entities (XXE)
- [ ] Understand XXE attack vectors
- [ ] Test file disclosure
- [ ] Test SSRF via XXE
- [ ] Study XML parser configurations
- [ ] Complete CTF Challenge #11 (200 points)

**XXE Payloads**:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

#### Day 6-7: Insecure Deserialization
- [ ] Study serialization formats (Pickle, JSON)
- [ ] Test deserialization vulnerabilities
- [ ] Create malicious payloads
- [ ] Complete CTF Challenge #12 (250 points)

### Week 2: API Security

#### Day 8-10: OWASP API Top 10
- [ ] Study BOLA in depth
- [ ] Test BOPLA (Broken Object Property Level Authorization)
- [ ] Test Mass Assignment vulnerabilities
- [ ] Understand API rate limiting
- [ ] Complete CTF Challenges #13-14 (500 points)

**API Attack Patterns**:
```bash
# Mass Assignment
POST /api/vulnerable/user/update
{"username": "user", "role": "admin", "is_admin": true}

# BOPLA
GET /api/vulnerable/user/profile?fields=password,credit_card
```

#### Day 11-14: Server-Side Attacks
- [ ] Server-Side Request Forgery (SSRF)
- [ ] Path traversal attacks
- [ ] File upload vulnerabilities
- [ ] Remote code execution
- [ ] Complete CTF Challenge #15 (300 points)

### Week 3: Advanced Topics

#### Day 15-17: Chaining Vulnerabilities
- [ ] Combine XSS + CSRF
- [ ] Chain SSRF + XXE
- [ ] Escalate privileges via multiple vulns
- [ ] Complete CTF Challenges #16-17 (600 points)

#### Day 18-21: Defense Analysis
- [ ] Study all secure implementations
- [ ] Understand defense-in-depth
- [ ] Review input validation techniques
- [ ] Analyze rate limiting strategies
- [ ] Complete final challenge #18 (300 points)

---

## ⚡ Advanced Path

**Target Audience**: Experienced security professionals
**Duration**: 1-2 weeks
**Goal**: Master all challenges, contribute to project

### Week 1: Speed Run

#### Day 1-3: Rapid Assessment
- [ ] Test all 40+ vulnerable endpoints
- [ ] Document all vulnerabilities
- [ ] Complete all 18 CTF challenges
- [ ] Target score: 2,700 points (100%)

#### Day 4-5: Automation
- [ ] Write custom exploitation scripts
- [ ] Automate vulnerability detection
- [ ] Create Burp Suite extensions
- [ ] Develop custom Postman tests

#### Day 6-7: Code Analysis
- [ ] Review entire codebase
- [ ] Understand all defense mechanisms
- [ ] Identify potential improvements
- [ ] Study ML-based AI detection

### Week 2: Contribution

#### Day 8-10: Research
- [ ] Find undocumented vulnerabilities
- [ ] Test edge cases
- [ ] Perform code review
- [ ] Document findings

#### Day 11-14: Give Back
- [ ] Create new CTF challenges
- [ ] Improve documentation
- [ ] Submit pull requests
- [ ] Help other learners

---

## 🎯 Certification Preparation

### For CEH (Certified Ethical Hacker)

**Focus Areas**:
- [ ] All injection techniques
- [ ] Authentication bypass
- [ ] Session hijacking
- [ ] Reconnaissance techniques
- [ ] Tool proficiency (Burp, ZAP, SQLMap)

**AegisForge Mapping**:
- Module 13: Web Application Hacking → All vulnerable endpoints
- Module 14: SQL Injection → SQLi challenges
- Module 15: Hacking Wireless → N/A

**Practice Schedule**: 1 hour daily for 2 weeks

### For OSCP (Offensive Security Certified Professional)

**Focus Areas**:
- [ ] Manual exploitation (avoid automation)
- [ ] Privilege escalation paths
- [ ] Code review and analysis
- [ ] Custom payload development
- [ ] Detailed reporting

**AegisForge Mapping**:
- Manual testing of all endpoints
- Develop custom exploits
- Chain vulnerabilities
- Document attack paths

### For OSWE (Offensive Security Web Expert)

**Focus Areas**:
- [ ] White-box code review
- [ ] Advanced XSS and XXE
- [ ] Custom exploit development
- [ ] Bypassing filters and WAF
- [ ] Source code analysis

**AegisForge Mapping**:
- Review all Python source code
- Study defense implementations
- Create bypasses for secure endpoints
- Contribute code improvements

---

## 👨‍💻 Developer Focus Path

**Target Audience**: Developers learning secure coding
**Duration**: 2-3 weeks
**Goal**: Write secure code, understand defenses

### Week 1: Vulnerability Understanding

#### Day 1-7: Attack Perspective
- [ ] Test all vulnerable endpoints
- [ ] Understand attacker mindset
- [ ] Complete beginner CTF challenges
- [ ] Document exploitation techniques

### Week 2: Defense Implementation

#### Day 8-14: Secure Coding
- [ ] Study all secure endpoint implementations
- [ ] Understand input validation patterns
- [ ] Learn output encoding techniques
- [ ] Study security headers
- [ ] Review authentication/authorization code

**Key Files to Study**:
```
defenses/
├── input_validation.py
├── output_encoding.py
├── rate_limiting.py
├── access_control.py
└── security_headers.py
```

### Week 3: Application

#### Day 15-21: Practice
- [ ] Write secure API endpoints
- [ ] Implement security controls
- [ ] Review code with security mindset
- [ ] Contribute secure code examples

---

## 📊 Progress Tracking

### Beginner Milestones
- [ ] 5 CTF challenges completed (500 points)
- [ ] Postman collection fully tested
- [ ] Basic tool setup (ZAP or Burp)
- [ ] Understanding of OWASP Top 10

### Intermediate Milestones
- [ ] 12 CTF challenges completed (1,500 points)
- [ ] Custom exploit scripts written
- [ ] Advanced tool usage
- [ ] Can explain all vulnerabilities

### Advanced Milestones
- [ ] All 18 CTF challenges (2,700 points)
- [ ] Leaderboard top 10
- [ ] Automation framework developed
- [ ] Contributed to project

---

## 🎓 Recommended External Resources

### Books
- "The Web Application Hacker's Handbook" by Stuttard & Pinto
- "Real-World Bug Hunting" by Peter Yaworski
- "OWASP Testing Guide v4"

### Online Courses
- OWASP WebGoat
- PortSwigger Web Security Academy
- HackerOne Hacktivity

### Practice Platforms
- HackTheBox
- TryHackMe
- PentesterLab

---

## 🏆 Completion Certificate

After completing your chosen path:

1. **Document your journey**
2. **Complete final assessment**
3. **Share learnings with community**
4. **Contribute to AegisForge**

---

## 📚 Additional Resources

- [API_DOCUMENTATION.md](../../API_DOCUMENTATION.md)
- [OWASP_COVERAGE_MATRIX.md](../../OWASP_COVERAGE_MATRIX.md)
- [CONTRIBUTING.md](../../CONTRIBUTING.md)

---

**Choose your path and start learning! The journey to security mastery begins now.** 🛡️
