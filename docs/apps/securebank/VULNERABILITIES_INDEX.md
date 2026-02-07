# SecureBank Vulnerability Documentation Index

## Overview

This directory contains comprehensive documentation for all 6 major vulnerabilities demonstrated in the SecureBank training platform. Each vulnerability guide follows a consistent 7-section structure designed for hands-on learning.

## Vulnerability Guides

### 1. [SQL Injection (04_SQL_INJECTION.md)](04_SQL_INJECTION.md)
**Lines:** 1,005 | **Size:** 32 KB  
**CVEs Covered:** CVE-2019-1010293, Multiple  
**Real-World Cost:** Up to $256 million (TJX breach)

Learn how attackers bypass authentication using SQL injection, extract sensitive data, and how to prevent it using parameterized queries.

**Key Topics:**
- Login bypass with `' OR '1'='1'--`
- UNION-based data extraction
- Parameterized queries in Python/SQLite
- SQLMap automation
- Error-based SQL injection

---

### 2. [Insecure Direct Object References - IDOR (05_IDOR.md)](05_IDOR.md)
**Lines:** 1,269 | **Size:** 39 KB  
**CVEs Covered:** CVE-2020-24590, Multiple  
**Real-World Cost:** Up to $1.4 billion (Equifax breach)

Understand how attackers access other users' accounts by manipulating ID parameters, and implement proper authorization checks.

**Key Topics:**
- Account enumeration via sequential IDs
- Authorization vs Authentication
- Database-level access control
- Python account scanner
- Burp Suite Intruder enumeration

---

### 3. [Race Conditions (06_RACE_CONDITION.md)](06_RACE_CONDITION.md)
**Lines:** 1,453 | **Size:** 48 KB  
**CVEs Covered:** CVE-2021-22911, Multiple  
**Real-World Cost:** Up to $50+ million (Robinhood infinite leverage)

Discover how concurrent requests can bypass balance checks, leading to negative balances and money creation, plus learn proper transaction locking.

**Key Topics:**
- Time-of-Check to Time-of-Use (TOCTOU) bugs
- Python concurrent.futures exploitation
- Threading barriers for synchronized attacks
- Mutex locks and database transactions
- BEGIN EXCLUSIVE in SQLite

---

### 4. [Cross-Site Scripting - XSS (07_XSS.md)](07_XSS.md)
**Lines:** 1,560 | **Size:** 50 KB  
**CVEs Covered:** CVE-2019-11358, CVE-2020-11022  
**Real-World Cost:** Up to $230 million (British Airways GDPR fine)

Master XSS attacks through transaction notes, session hijacking, and implement proper output encoding and Content Security Policy.

**Key Topics:**
- Stored XSS in transaction notes
- Session cookie theft with `document.cookie`
- DOM-based XSS attacks
- HTML entity encoding with `escape_html()`
- Content Security Policy (CSP) headers

---

### 5. [Mass Assignment (08_MASS_ASSIGNMENT.md)](08_MASS_ASSIGNMENT.md)
**Lines:** 1,448 | **Size:** 44 KB  
**CVEs Covered:** CVE-2012-1098 (GitHub), CVE-2013-1857  
**Real-World Cost:** Up to $50+ million (Rails breaches)

Learn how attackers inject unauthorized fields like `role: admin` in profile updates, and implement field whitelisting.

**Key Topics:**
- Privilege escalation to admin
- Balance manipulation
- Field whitelisting vs blacklisting
- Ruby on Rails strong parameters
- Parameter pollution attacks

---

### 6. [Cross-Site Request Forgery - CSRF (09_CSRF.md)](09_CSRF.md)
**Lines:** 1,505 | **Size:** 54 KB  
**CVEs Covered:** CVE-2019-8331, Multiple  
**Real-World Cost:** Up to €2.4 million (ING Bank)

Understand how attackers trick logged-in users into making unauthorized transfers, and implement CSRF token protection.

**Key Topics:**
- Auto-submit form attacks
- Hidden iframe exploits
- CSRF token generation with `secrets.token_hex()`
- Double-submit cookie pattern
- SameSite cookie attribute

---

## Documentation Structure

Each guide follows this consistent 7-section format:

### 1. Overview
- What is the vulnerability?
- Why does it exist in banking applications?
- Real-world financial impact with specific dollar amounts

### 2. The Vulnerable Code
- Actual code from `securebank_red_api.py`
- Line-by-line vulnerability breakdown
- Visual attack flow diagrams (ASCII art)

### 3. Exploitation Walkthrough
- Step-by-step instructions
- Postman request examples
- Burp Suite techniques
- Expected results and outputs
- Screenshot placeholders

### 4. The Secure Code
- Fixed implementation from `securebank_blue_api.py`
- Line-by-line security analysis
- Visual secure flow diagrams
- Defense mechanisms explained

### 5. Real-World Examples
- Anonymized bug bounty reports with payout amounts
- CVE references with CVSS scores
- News articles about actual breaches
- Financial impact breakdowns

### 6. Hands-On Exercises
- 3-5 progressive exercises (beginner → advanced)
- Complete solutions provided
- Clear success criteria
- Building on previous concepts

### 7. Tool Integration
- Postman collection examples
- Burp Suite configuration
- OWASP ZAP scanning
- SQLMap commands
- Custom Python scripts
- cURL examples

---

## Tools Covered

Every vulnerability guide includes practical examples for:

- **Postman** - API testing, collection runner, environment variables
- **Burp Suite** - Proxy, Repeater, Intruder, Scanner, Extensions
- **OWASP ZAP** - Active scan, fuzzer, spider, authentication
- **SQLMap** - Automated SQL injection testing (for SQLi guide)
- **Python** - Custom exploitation scripts using `requests`, `concurrent.futures`
- **cURL** - Command-line HTTP testing
- **ffuf** - Parameter fuzzing
- **Browser DevTools** - Network inspection, console exploitation

---

## Real-World Breach Data

Documentation includes actual financial impact from real security incidents:

| Vulnerability | Notable Breach | Financial Impact |
|---------------|----------------|------------------|
| SQL Injection | Heartland Payment Systems | $140 million |
| SQL Injection | TJX Companies | $256 million |
| IDOR | Equifax | $1.4 billion |
| IDOR | T-Mobile | $350 million |
| Race Condition | Robinhood | $50+ million |
| Race Condition | TD Ameritrade | $5.2 million |
| XSS | British Airways | $230 million (GDPR) |
| XSS | Magecart Campaigns | $100+ million |
| Mass Assignment | GitHub (CVE-2012-1098) | Service disruption |
| CSRF | ING Bank | €2.4 million |

---

## Learning Path

### Beginner Path (Start Here)
1. **SQL Injection** - Easiest to understand and exploit
2. **IDOR** - Simple concept with major impact
3. **XSS** - Visual results, easy to demonstrate

### Intermediate Path
4. **Mass Assignment** - Requires understanding of object binding
5. **CSRF** - Needs understanding of session management

### Advanced Path
6. **Race Conditions** - Most complex, requires concurrency knowledge

---

## CVE References

Complete list of CVEs covered across all guides:

- **CVE-2019-1010293** - Barclays Online Banking SQLi
- **CVE-2020-24590** - E-Banking IDOR
- **CVE-2021-22911** - Banking API Race Condition
- **CVE-2019-11358** - jQuery XSS
- **CVE-2020-11022** - jQuery 3.5.0 XSS
- **CVE-2012-1098** - GitHub Mass Assignment
- **CVE-2013-1857** - Django Mass Assignment
- **CVE-2019-8331** - Bootstrap CSRF
- **CVE-2008-0166** - Financial Application CSRF

---

## Quick Reference

### File Sizes
```
Total Documentation: 267 KB / 8,240 lines
Average per file: 44.5 KB / 1,373 lines
```

### Reading Time
Approximately 6-8 hours to read all guides completely.

### Hands-On Time
Approximately 15-20 hours to complete all exercises.

---

## Using These Guides

### For Students
1. Read the Overview to understand the vulnerability
2. Study the Vulnerable Code section carefully
3. Follow the Exploitation Walkthrough step-by-step
4. Compare with the Secure Code
5. Review Real-World Examples for context
6. Complete all Hands-On Exercises
7. Practice with different Tools

### For Instructors
- Each guide is self-contained and can be taught independently
- Exercises have solutions for grading
- Real-world examples provide motivation
- Tool integration supports lab environments
- Recommended teaching order: SQL → IDOR → XSS → Mass Assignment → CSRF → Race

### For Security Professionals
- Quick reference for common vulnerabilities
- Code examples for secure implementation
- Tool integration for penetration testing
- CVE references for research
- Real-world impact data for risk assessment

---

## Additional Resources

### SecureBank Documentation
- [Setup Guide](01_SETUP_GUIDE.md) - Installation and configuration
- [User Guide](02_USER_GUIDE.md) - Using the application
- [Architecture](03_ARCHITECTURE.md) - System design
- [Testing with Burp](11_TESTING_WITH_BURP.md) - Burp Suite integration
- [Testing with SQLMap](12_TESTING_WITH_SQLMAP.md) - SQLMap usage
- [Testing with ZAP](13_TESTING_WITH_ZAP.md) - OWASP ZAP guide

### External Resources
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- SANS Secure Coding: https://www.sans.org/secure-coding/

---

## Contributing

Found an error or have a suggestion? Please open an issue or submit a pull request.

---

## License

This documentation is part of the AegisForge SecureBank training platform.

---

**Last Updated:** February 2024  
**Version:** 1.0  
**Authors:** AegisForge Security Team
