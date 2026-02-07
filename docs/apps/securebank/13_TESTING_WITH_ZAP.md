# 🕷️ Testing SecureBank with OWASP ZAP

**Automated Web Application Security Scanning**

OWASP ZAP (Zed Attack Proxy) is the world's most popular free web application security scanner. This guide teaches you how to use ZAP to discover all 6 vulnerabilities in SecureBank through automated scanning, manual testing, and active attacks.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [What is OWASP ZAP?](#what-is-owasp-zap)
3. [Installation & Setup](#installation--setup)
4. [Quick Start Automated Scan](#quick-start-automated-scan)
5. [Manual Exploration](#manual-exploration)
6. [Active Scanning](#active-scanning)
7. [Finding SQL Injection](#finding-sql-injection)
8. [Finding IDOR](#finding-idor)
9. [Finding XSS](#finding-xss)
10. [Finding Other Vulnerabilities](#finding-other-vulnerabilities)
11. [Generating Reports](#generating-reports)
12. [Advanced Features](#advanced-features)
13. [Troubleshooting](#troubleshooting)
14. [Best Practices](#best-practices)

---

## 🎯 Overview

OWASP ZAP is a free, open-source web application security scanner maintained by the OWASP Foundation. It's designed to be used by people with a wide range of security experience - from developers to professional penetration testers.

### Why Use OWASP ZAP?

ZAP helps you find security vulnerabilities by:

- **Automated scanning**: Automatically crawl and scan web applications
- **Intercepting proxy**: See and modify traffic like Burp Suite
- **Active attacks**: Test for vulnerabilities with real exploit attempts
- **Passive scanning**: Find issues without sending attack payloads
- **Reporting**: Generate professional security reports
- **API support**: Test REST APIs and GraphQL endpoints

### ZAP vs. Other Tools

**ZAP vs. Burp Suite**:
- ✅ ZAP is completely free and open-source
- ✅ ZAP has better automation for beginners
- ✅ ZAP includes active scanner in free version
- ❌ Burp has better manual testing features
- ❌ Burp has more advanced users/commercial support

**ZAP vs. SQLMap**:
- ✅ ZAP tests for many vulnerability types (not just SQL injection)
- ✅ ZAP has a graphical user interface
- ✅ ZAP crawls entire applications automatically
- ❌ SQLMap is more specialized and powerful for SQL injection
- ❌ SQLMap has better database extraction features

### What You'll Learn

By the end of this guide, you'll be able to:

- ✅ Install and configure OWASP ZAP
- ✅ Perform automated scans of web applications
- ✅ Use ZAP as an intercepting proxy
- ✅ Manually test for specific vulnerabilities
- ✅ Find SQL injection with ZAP's SQL injection scanner
- ✅ Discover access control issues (IDOR)
- ✅ Identify XSS vulnerabilities
- ✅ Generate professional security reports
- ✅ Use ZAP's API for automated testing
- ✅ Integrate ZAP into CI/CD pipelines

---

## 🔍 What is OWASP ZAP?

OWASP ZAP (Zed Attack Proxy) is a comprehensive web application security testing tool. It was created by Simon Bennetts and has been actively developed by the OWASP community since 2010.

### Key Components

**1. Spider/Crawler**
- Automatically discovers all pages and endpoints in your application
- Follows links, submits forms, and maps the application structure
- Identifies potential attack surfaces
- Creates a site tree showing all discovered resources

**2. Passive Scanner**
- Analyzes HTTP requests and responses without sending attacks
- Finds issues like missing security headers, cookie problems
- Safe to run on production systems
- Runs automatically as you browse

**3. Active Scanner**
- Sends real attack payloads to test for vulnerabilities
- Tests for SQL injection, XSS, path traversal, and more
- Can impact application performance
- Should only be used on authorized test systems

**4. Intercepting Proxy**
- Sits between your browser and the application
- Allows you to view and modify requests/responses
- Similar to Burp Suite's proxy
- Useful for manual testing and learning

**5. Fuzzer**
- Sends many variations of input to test application behavior
- Useful for finding input validation issues
- Can test specific parameters or entire requests
- Includes built-in payload lists

**6. API Scanner**
- Imports OpenAPI/Swagger definitions
- Tests API endpoints automatically
- Validates API security controls
- Supports REST and GraphQL

**7. Report Generator**
- Creates professional security assessment reports
- Multiple formats: HTML, XML, JSON, Markdown
- Includes vulnerability details and remediation advice
- Can be customized with templates

### ZAP Scanning Modes

**1. Safe Mode**
- Only passive scanning
- No active attacks sent
- Safe for production systems
- Limited vulnerability detection

**2. Protected Mode** (Recommended)
- Requires you to define target scope
- Active scanning only on in-scope targets
- Prevents accidental attacks on other sites
- Best for learning and testing

**3. Attack Mode**
- No restrictions on scanning
- Will attack any site you visit
- Dangerous for production environments
- Only use in isolated test labs

### What ZAP Can Find

ZAP tests for dozens of vulnerability types:

**Injection Attacks**:
- SQL Injection
- Command Injection
- LDAP Injection
- XPath Injection
- Code Injection

**Access Control**:
- Broken Authentication
- Session Management Issues
- Authorization Bypass
- IDOR (Insecure Direct Object References)

**Client-Side Attacks**:
- Cross-Site Scripting (XSS)
- HTML Injection
- Content Security Policy Issues

**Configuration Issues**:
- Missing Security Headers
- Weak SSL/TLS Configuration
- Information Disclosure
- Debug Features Enabled

**Logic Flaws**:
- CSRF (Cross-Site Request Forgery)
- Business Logic Vulnerabilities
- Race Conditions (limited)

---

## 📦 Installation & Setup

### Step 1: Install Java

ZAP requires Java 11 or higher.

**Check Java version**:
```bash
java -version
```

**Install Java (if needed)**:

**Ubuntu/Debian**:
```bash
sudo apt update
sudo apt install openjdk-17-jdk
```

**macOS**:
```bash
brew install openjdk@17
```

**Windows**:
Download from [adoptium.net](https://adoptium.net/)

### Step 2: Download and Install ZAP

**Option 1: Download Installer (Recommended)**

1. Visit [zaproxy.org/download](https://www.zaproxy.org/download/)
2. Download the installer for your platform:
   - **Windows**: `.exe` installer
   - **macOS**: `.dmg` installer
   - **Linux**: `.sh` installer

**Option 2: Using Package Manager**

**Kali Linux** (pre-installed):
```bash
zaproxy
```

**Ubuntu/Debian** (via Snap):
```bash
sudo snap install zaproxy --classic
```

**macOS** (via Homebrew):
```bash
brew install --cask owasp-zap
```

**Arch Linux**:
```bash
sudo pacman -S zaproxy
```

**Option 3: Docker** (Advanced):
```bash
docker pull zaproxy/zap-stable
docker run -u zap -p 8080:8080 zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080
```

### Step 3: Launch ZAP

**Windows/macOS**:
- Double-click the ZAP application icon

**Linux**:
```bash
zaproxy
# Or if installed via snap:
snap run zaproxy
```

**First Launch**:
1. Choose "No, I do not want to persist this session" (for now)
2. Select "Protected Mode" (recommended for learning)
3. Click "Start"

**Screenshot Placeholder**: [ZAP startup screen showing mode selection]

### Step 4: Configure Browser

ZAP works best when you configure your browser to use it as a proxy.

**Recommended: Firefox with FoxyProxy** (same as Burp Suite)

1. **Install Firefox**
2. **Install FoxyProxy Standard** extension
3. **Configure FoxyProxy**:
   - Click FoxyProxy icon → Options
   - Add New Proxy
   - Title: "OWASP ZAP"
   - Proxy Type: HTTP
   - IP: `localhost` or `127.0.0.1`
   - Port: `8080` (ZAP default)
   - Save

4. **Enable proxy**:
   - Click FoxyProxy icon
   - Select "OWASP ZAP"

### Step 5: Install ZAP's Root Certificate

To intercept HTTPS traffic:

1. **Start ZAP**
2. **Browser proxy enabled**
3. **Visit**: `http://zap/`
4. **Click**: "Download ZAP Root CA Certificate"
5. **Save as**: `owasp_zap_root_ca.cer`

**Install in Firefox**:
- Settings → Privacy & Security → Certificates → View Certificates
- Authorities tab → Import
- Select `owasp_zap_root_ca.cer`
- Check "Trust this CA to identify websites"
- OK

**Install in Chrome/Edge (Windows)**:
- Settings → Privacy and security → Security → Manage certificates
- Trusted Root Certification Authorities → Import
- Select the certificate
- Follow the wizard

**macOS (System-wide)**:
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Downloads/owasp_zap_root_ca.cer
```

### Step 6: Verify Setup

1. **Enable proxy** in browser (FoxyProxy → OWASP ZAP)
2. **Visit**: `http://example.com`
3. **Check ZAP**: You should see the request in the **History** tab

If you see traffic, your setup is working! 🎉

---

## 🚀 Quick Start Automated Scan

The fastest way to scan SecureBank with ZAP is using the Automated Scan feature.

### Step 1: Start SecureBank

Ensure SecureBank is running:

```bash
cd /path/to/aegisforgee
python securityforge_api.py
```

Verify it's accessible: `http://localhost:5000/apps/securebank/red/login.html`

### Step 2: Launch Automated Scan

1. **In ZAP**, click the **Automated Scan** button (looks like a play icon with a clock)
2. **Enter URL**: `http://localhost:5000/apps/securebank/red/`
3. **Choose**: "Use traditional spider"
4. **Uncheck**: "Use ajax spider" (SecureBank is mostly traditional HTML)
5. **Click**: "Attack"

**Screenshot Placeholder**: [ZAP Automated Scan dialog with SecureBank URL entered]

### Step 3: Monitor Scan Progress

ZAP will:
1. **Spider** the application (discover all pages)
2. **Passive scan** (analyze traffic for basic issues)
3. **Active scan** (send attack payloads)

**Progress indicators**:
- Spider: Shows pages being discovered
- Active Scan: Shows % complete
- Alerts: Vulnerabilities found appear in real-time

**Time estimate**: 5-10 minutes for SecureBank

**Screenshot Placeholder**: [ZAP scanning in progress showing spider and active scanner status]

### Step 4: Review Results

When scanning completes:

1. **Click** the **Alerts** tab (left sidebar)
2. **Expand** alerts by severity:
   - 🔴 High (Critical vulnerabilities)
   - 🟠 Medium (Important issues)
   - 🟡 Low (Minor issues)
   - 🔵 Informational (Good to know)

**Expected findings for SecureBank Red Team**:
- 🔴 High: SQL Injection in login
- 🔴 High: Cross-Site Scripting (XSS)
- 🟠 Medium: CSRF tokens missing
- 🟠 Medium: Access control issues
- 🟡 Low: Information disclosure
- 🔵 Info: Missing security headers

**Screenshot Placeholder**: [ZAP Alerts tab showing vulnerabilities found in SecureBank]

### Step 5: Examine Individual Alerts

Click on any alert to see:
- **Description**: What the vulnerability is
- **URL**: Where it was found
- **Parameter**: Which input is vulnerable
- **Attack**: The payload that triggered it
- **Evidence**: Proof of vulnerability
- **Solution**: How to fix it
- **References**: Links to more information

**Screenshot Placeholder**: [ZAP alert detail showing SQL injection vulnerability details]

### Quick Win! 🎉

In just a few minutes, ZAP has automatically discovered multiple vulnerabilities in SecureBank. Now let's dive deeper into manual testing.

---

## 🔎 Manual Exploration

Automated scans are great, but manual exploration gives you deeper understanding and control.

### Step 1: Configure Target Scope

1. **Right-click** `http://localhost:5000` in the Sites tree
2. **Select**: "Include in Context" → "Default Context"
3. **Right-click** again → "Include in Context" → "New Context"
4. **Name it**: "SecureBank"
5. **Configure scope**:
   - Include: `http://localhost:5000/apps/securebank/.*`
   - Exclude: Other paths

This ensures ZAP only attacks SecureBank, not other sites.

### Step 2: Manual Browsing with Proxy

1. **Enable proxy** in browser
2. **Browse SecureBank manually**:
   - Visit login page
   - Try logging in (alice / password123)
   - Navigate through all pages
   - Try different features (transfer, profile, settings)

**As you browse**, ZAP will:
- Record all requests in the History tab
- Build the Sites tree
- Run passive scans automatically
- Highlight potential issues

**Screenshot Placeholder**: [ZAP Sites tree showing all SecureBank pages discovered through manual browsing]

### Step 3: Review Passive Scan Results

**Passive scanning** finds issues without sending attacks:

1. **Go to** Alerts tab
2. **Filter by**: Passive scan results (blue shield icon)
3. **Common passive findings**:
   - Missing security headers (X-Content-Type-Options, etc.)
   - Cookies without Secure flag
   - Information disclosure in comments
   - Weak SSL/TLS configuration

**Why passive scanning matters**:
- Safe to run on production
- Finds "low-hanging fruit"
- No performance impact
- Good starting point

### Step 4: Spider from Authenticated Session

ZAP's spider can discover more pages if you're logged in:

1. **Login** to SecureBank manually (through ZAP proxy)
2. **Right-click** on the dashboard request in History
3. **Select**: "Include in Context" → "SecureBank"
4. **Right-click** on the session cookie
5. **Select**: "Flag as session token" → "session"
6. **Tools** → **Spider** → Enter login URL
7. **Click**: "Start Scan"

This discovers authenticated pages that anonymous spider would miss.

### Step 5: Review Site Structure

The **Sites** tree shows all discovered resources:

```
http://localhost:5000
└── apps
    └── securebank
        └── red
            ├── login.html
            ├── dashboard.html
            ├── accounts.html
            ├── transfer.html
            ├── transactions.html
            ├── profile.html
            ├── settings.html
            └── api
                ├── auth
                │   └── login
                ├── accounts (multiple IDs)
                ├── transfer
                ├── users
                │   └── profile
                └── settings
```

This gives you a complete map of the attack surface.

---

## ⚡ Active Scanning

Active scanning sends real attack payloads to test for vulnerabilities. **Only use on authorized test systems!**

### Step 1: Configure Active Scan Policy

1. **Analyze** → **Scan Policy Manager**
2. **Select** "Default Policy"
3. **Configure thresholds**:
   - **Threshold**: How much testing (Off, Low, Medium, High)
   - **Strength**: Attack intensity (Low, Medium, High, Insane)
4. **For learning**, set most to **Medium/Medium**
5. **Save** as "SecureBank Policy"

**Screenshot Placeholder**: [ZAP Scan Policy Manager showing vulnerability categories]

### Step 2: Start Active Scan

**Method 1: Scan entire site**:
1. **Right-click** on `http://localhost:5000/apps/securebank/red/` in Sites tree
2. **Select**: "Attack" → "Active Scan"
3. **Choose policy**: SecureBank Policy
4. **Click**: "Start Scan"

**Method 2: Scan specific page**:
1. **Find a request** in History (e.g., login POST)
2. **Right-click** → "Attack" → "Active Scan"
3. **Customize** if needed
4. **Start**

### Step 3: Monitor Active Scan

**Active Scan tab** shows:
- **Progress**: Percentage complete
- **Requests**: Total requests sent
- **Alerts**: Vulnerabilities found
- **Time elapsed**: How long it's been running

**Estimated time**: 10-30 minutes for SecureBank (depends on policy)

**Screenshot Placeholder**: [ZAP Active Scan progress showing tests being performed]

### Step 4: Analyze Active Scan Results

When complete, review **Alerts**:

**SQL Injection**:
- **Alert**: "SQL Injection"
- **Risk**: High
- **URL**: `/apps/securebank/api/red/auth/login`
- **Parameter**: username
- **Attack**: `' OR '1'='1' --`
- **Evidence**: Different response when injecting SQL

**Cross-Site Scripting**:
- **Alert**: "Cross Site Scripting (Reflected/Stored)"
- **Risk**: High
- **URL**: `/apps/securebank/api/red/transfer`
- **Parameter**: note
- **Attack**: `<script>alert(1)</script>`
- **Evidence**: Script reflected in page

### Step 5: Compare Red vs Blue Team

1. **Scan Red Team** (vulnerable version)
2. **Note vulnerabilities found**
3. **Scan Blue Team** (secure version):
   - URL: `http://localhost:5000/apps/securebank/blue/`
4. **Compare results**

**Expected results**:
- **Red Team**: Multiple high/medium alerts
- **Blue Team**: Significantly fewer alerts (should be fixed)

**Screenshot Placeholder**: [Side-by-side comparison of Red Team vs Blue Team scan results]

---

## 💉 Finding SQL Injection

Let's focus specifically on finding and exploiting SQL injection with ZAP.

### Step 1: Enable SQL Injection Scanner

1. **Tools** → **Options** → **Active Scan**
2. **Input Vectors**:
   - Enable all input vectors (Query, POST, Cookies, Headers)
3. **Policy** → **Injection**:
   - SQL Injection: **High** threshold and strength
4. **Apply**

### Step 2: Scan Login Endpoint

1. **Browse** to login page
2. **Enter** test credentials (doesn't matter what)
3. **Submit** login form
4. **Find** the POST request in History
5. **Right-click** → Attack → Active Scan
6. **Wait** for scan to complete

### Step 3: Review SQL Injection Alert

When ZAP finds SQL injection:

**Alert details**:
```
Alert: SQL Injection
Risk: High
Confidence: Medium
URL: http://localhost:5000/apps/securebank/api/red/auth/login
Parameter: username
Attack: admin' OR '1'='1' --
Evidence: User logged in successfully
```

**What ZAP tested**:
- Boolean-based payloads (`' OR '1'='1'`)
- Error-based payloads (`' AND 1=CONVERT(int, 'a')`)
- Time-based payloads (`'; WAITFOR DELAY '00:00:05'--`)
- Union-based payloads (`' UNION SELECT NULL--`)

**Screenshot Placeholder**: [ZAP SQL Injection alert showing detected vulnerability]

### Step 4: Manual Verification

**Test manually** using ZAP's Request Editor:

1. **Right-click** the login request → "Open/Resend with Request Editor"
2. **Modify** the username parameter:
   ```json
   {"username":"admin' OR '1'='1' --","password":"anything"}
   ```
3. **Click** "Send"
4. **Observe** response: Successful login!

This confirms the SQL injection is exploitable.

### Step 5: Test Different Payloads

Use ZAP's **Fuzzer** to test multiple SQL injection payloads:

1. **Right-click** the login request → "Attack" → "Fuzz"
2. **Highlight** the username value
3. **Click** "Add"
4. **Choose** "File Fuzzers" → "jbrofuzz" → "SQL Injection"
5. **Click** "Add" → "OK"
6. **Start Fuzzer**

**Screenshot Placeholder**: [ZAP Fuzzer testing multiple SQL injection payloads]

ZAP will test dozens of SQL injection variations and show which ones succeed.

### Expected Results

**Successful payloads** (HTTP 200, different response):
- `admin' OR '1'='1' --`
- `admin'--`
- `' OR 1=1 --`
- `' OR '1'='1'/*`

**Failed payloads** (HTTP 401, error message):
- `admin' AND '1'='2'--`
- Normal text without SQL syntax

---

## 🔓 Finding IDOR

IDOR vulnerabilities require testing if users can access resources they shouldn't. ZAP can help find these.

### Step 1: Enable Access Control Testing

1. **Tools** → **Options** → **Active Scan**
2. **Policy** → **Access Control**:
   - "Insecure Direct Object Reference": High
3. **Apply**

### Step 2: Identify Resource Access Patterns

Browse SecureBank while logged in and look for resource access:

**Pattern**: `/api/red/accounts/2` (Alice's account)

**Hypothesis**: Changing `2` to `1` might show admin's account (IDOR)

### Step 3: Test Manually with ZAP

1. **Login** as Alice
2. **Visit** accounts page
3. **Find** the request: `GET /api/red/accounts/2`
4. **Right-click** → "Open/Resend with Request Editor"
5. **Change** account ID to `1`:
   ```
   GET /api/red/accounts/1 HTTP/1.1
   ```
6. **Send**

**Expected result**: You see admin's account details (IDOR confirmed)

**Screenshot Placeholder**: [ZAP Request Editor showing IDOR exploitation by changing account ID]

### Step 4: Automate IDOR Testing with Fuzzer

1. **Right-click** account request → "Attack" → "Fuzz"
2. **Highlight** the account ID number `2`
3. **Add** → Choose "Numberzz"
4. **Configure**:
   - From: 1
   - To: 100
   - Step: 1
5. **Start Fuzzer**

**Screenshot Placeholder**: [ZAP Fuzzer results showing different account IDs and responses]

### Step 5: Analyze Results

**Look for**:
- **Different response codes**: 200 (found) vs 404 (not found)
- **Different content length**: Varies with each account
- **Different response content**: Different user data

**Successful IDOR**:
```
Request: GET /api/red/accounts/1
Response: 200 OK
Content: {"account_id": 1, "user": "admin", "balance": 25000}

Request: GET /api/red/accounts/3
Response: 200 OK
Content: {"account_id": 3, "user": "bob", "balance": 3000}
```

All account IDs return data, even though you're logged in as Alice (user_id=2).

### Step 6: ZAP Access Control Testing Add-on

For advanced IDOR testing:

1. **Manage Add-ons** → **Marketplace**
2. **Search**: "Access Control"
3. **Install**: "Access Control Testing"
4. **Configure**:
   - Define user roles (admin, user)
   - Define access rules
   - Run tests automatically

This automates testing if Alice can access admin resources.

---

## 🚨 Finding XSS

Cross-Site Scripting is one of ZAP's strengths. Let's find XSS in SecureBank.

### Step 1: Enable XSS Scanner

1. **Tools** → **Options** → **Active Scan**
2. **Policy** → **Injection**:
   - "Cross Site Scripting (Reflected)": High
   - "Cross Site Scripting (Persistent)": High
3. **Apply**

### Step 2: Identify Input Points

XSS can occur anywhere user input is displayed:
- Login error messages
- Search results
- Profile information
- **Transaction notes** ← Most likely in SecureBank

### Step 3: Test Transaction Notes for XSS

1. **Login** to SecureBank
2. **Make a transfer** with note: `<script>alert('XSS')</script>`
3. **View** transactions page
4. **Check** if script executes (it will in Red Team)

### Step 4: ZAP Passive XSS Detection

ZAP's passive scanner may flag this:

**Alert**:
```
Alert: Cross Site Scripting (Reflected)
Risk: High
URL: http://localhost:5000/apps/securebank/api/red/transfer
Parameter: note
Evidence: User input reflected without encoding
```

### Step 5: Active XSS Scanning

For thorough testing:

1. **Right-click** transfer request → "Attack" → "Active Scan"
2. **Enable** only XSS tests (faster)
3. **Start scan**

**ZAP will test**:
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`
- `<svg onload=alert(1)>`
- `" onload="alert(1)`
- Many more variations

**Screenshot Placeholder**: [ZAP XSS scanner results showing vulnerable parameter]

### Step 6: Use XSS Fuzzer

Test custom XSS payloads:

1. **Right-click** transfer request → "Attack" → "Fuzz"
2. **Highlight** note field
3. **Add** → "File Fuzzers" → "jbrofuzz" → "XSS"
4. **Start Fuzzer**

**Results show**:
- Which payloads succeeded
- Response differences
- Evidence of XSS execution

### Step 7: DOM XSS Detection

For client-side XSS, ZAP has an add-on:

1. **Manage Add-ons** → **Marketplace**
2. **Install**: "DOM XSS Scanner"
3. **Scan** pages with JavaScript
4. **Review** alerts for DOM-based XSS

### Expected Results

**Stored XSS** (most severe):
- Payload stored in database
- Executes for all users viewing the data
- Found in transaction notes

**Reflected XSS**:
- Payload in URL/input reflected in response
- Executes only for the victim clicking link
- Less common in SecureBank

---

## 🔍 Finding Other Vulnerabilities

### Finding CSRF

**Manual test**:
1. **Make** a settings change in SecureBank
2. **Find** the request in ZAP History
3. **Check** if CSRF token is present
4. **Right-click** → "Open/Resend with Request Editor"
5. **Remove** CSRF token (if present) or change its value
6. **Send** - If it still works, CSRF is vulnerable

**ZAP detection**:
- Passive scanner looks for missing CSRF tokens
- Alert: "Absence of Anti-CSRF Tokens"

### Finding Mass Assignment

**Manual test**:
1. **Find** profile update request
2. **Note** parameters sent: `{"full_name": "Alice", "email": "..."}`
3. **Add** hidden parameter: `{"full_name": "Alice", "email": "...", "is_admin": true}`
4. **Send** and verify if privilege escalation works

**ZAP may not automatically detect this** - requires manual testing or custom scripts.

### Finding Race Conditions

**Manual test** (difficult with ZAP):
1. **Find** transfer request
2. **Right-click** → "Open/Resend with Request Editor"
3. **Send** multiple times very quickly
4. **Check** if balance goes negative

**Better tools for race conditions**: Burp Intruder (Pro), Turbo Intruder

### Finding Information Disclosure

**ZAP passive scanner** finds:
- Comments in HTML revealing sensitive info
- Server banners showing versions
- Stack traces with internal paths
- Debug features enabled

**Active scanner** tests:
- Directory listings
- Backup files (.bak, .old, ~)
- Source code disclosure
- Error messages revealing info

### Finding Weak Authentication

**ZAP tests**:
- Weak password requirements
- Missing account lockout
- Session fixation
- Session timeout issues

**Add-on**: "Authentication Helper" for testing authentication flows

---

## 📄 Generating Reports

After scanning, generate professional reports to document findings.

### Step 1: Generate HTML Report

1. **Report** → **Generate HTML Report**
2. **Choose**:
   - Title: "SecureBank Security Assessment"
   - Report by: Your name
   - Description: Brief overview
   - Include: All alerts (or filter by risk)
3. **Save as**: `securebank_report.html`
4. **Open** in browser

**Screenshot Placeholder**: [ZAP HTML report showing professional vulnerability documentation]

### Step 2: Generate XML Report

For parsing or importing into other tools:

```bash
# Via ZAP API
curl "http://localhost:8080/JSON/core/action/xmlreport/" > report.xml
```

Or: **Report** → **Export Report** → Choose XML format

### Step 3: Generate Markdown Report

For documentation or GitHub issues:

1. **Report** → **Export Report**
2. **Format**: Choose Markdown
3. **Save as**: `securebank_findings.md`

**Example output**:
```markdown
# Security Assessment Report

## High Risk Vulnerabilities

### SQL Injection
- **URL**: http://localhost:5000/apps/securebank/api/red/auth/login
- **Parameter**: username
- **Payload**: admin' OR '1'='1' --
- **Impact**: Complete authentication bypass

### Cross-Site Scripting (Stored)
- **URL**: http://localhost:5000/apps/securebank/api/red/transfer
- **Parameter**: note
- **Payload**: <script>alert(1)</script>
- **Impact**: Session hijacking, credential theft
```

### Step 4: Customize Report Template

For professional engagements:

1. **Tools** → **Options** → **Report**
2. **Customize**:
   - Company logo
   - Color scheme
   - Report sections
   - Vulnerability descriptions
3. **Save template**

### Step 5: Export Alerts to CSV

For spreadsheet analysis:

1. **Alerts tab** → Right-click header
2. **Export** → Choose CSV
3. **Save** as `vulnerabilities.csv`

Open in Excel/Google Sheets for filtering, sorting, and analysis.

---

## 🚀 Advanced Features

### ZAP API

Control ZAP programmatically:

**Start ZAP daemon**:
```bash
zap.sh -daemon -port 8080 -config api.key=your-api-key
```

**API examples**:

**Spider a target**:
```bash
curl "http://localhost:8080/JSON/spider/action/scan/?url=http://localhost:5000"
```

**Start active scan**:
```bash
curl "http://localhost:8080/JSON/ascan/action/scan/?url=http://localhost:5000"
```

**Get alerts**:
```bash
curl "http://localhost:8080/JSON/alert/view/alerts/"
```

**Use in CI/CD**:
```yaml
# GitHub Actions example
- name: ZAP Scan
  uses: zaproxy/action-full-scan@v0.4.0
  with:
    target: 'http://localhost:5000'
```

### Authentication Scripts

For testing authenticated portions:

1. **Tools** → **Options** → **Authentication**
2. **Choose method**:
   - Form-based (for SecureBank)
   - Script-based (for complex auth)
   - JSON-based (for APIs)
3. **Configure**:
   - Login URL
   - Username/password fields
   - Logged-in indicator
4. **Save**

ZAP will automatically re-authenticate if session expires.

### Custom Scan Rules

Write your own vulnerability checks:

1. **Manage Add-ons** → **Installed**
2. **Script Console** → New Script
3. **Type**: Active/Passive Scan Rule
4. **Language**: JavaScript, Python, etc.

**Example** (detect custom vulnerability):
```python
def scan(as, msg, param, value):
    # Your custom scan logic
    if "vulnerable_pattern" in msg.getResponseBody().toString():
        as.raiseAlert(risk, confidence, alert_name, description)
```

### Breakpoints

Pause requests for manual inspection:

1. **Set breakpoint**: Right-click request → "Break..."
2. **Configure**: Break on all requests, or specific URLs/methods
3. **When triggered**: Request pauses, allowing you to modify it
4. **Continue**: Forward the modified request

Similar to Burp Proxy's intercept feature.

### Collaboration Features

**Share ZAP session**:
1. **File** → **Persist Session** → Save location
2. **Share** the session file with team members
3. **Others open**: File → Open Session

**Export/Import context**:
- Contexts (scope, authentication) can be exported
- Share across team for consistent testing

---

## 🔧 Troubleshooting

### Issue 1: ZAP Not Intercepting Traffic

**Symptoms**:
- Browser loads normally
- No requests appear in ZAP History

**Solutions**:
1. **Check proxy settings**:
   - Browser configured for localhost:8080?
   - ZAP proxy listener running? (Tools → Options → Local Proxies)
2. **Verify certificate**:
   - HTTPS sites require trusted ZAP certificate
   - Reinstall certificate if needed
3. **Check firewall**:
   - Allow ZAP through firewall
   - Try disabling firewall temporarily

### Issue 2: Active Scan Running Forever

**Symptoms**:
- Scan stuck at same percentage
- No new alerts appearing

**Solutions**:
1. **Check policy settings**:
   - High strength can take very long
   - Reduce to Medium for faster scans
2. **Review scope**:
   - Scanning too many URLs?
   - Restrict scope to specific paths
3. **Stop and restart**:
   - Active Scan tab → Stop
   - Review what was found
   - Restart with adjusted settings

### Issue 3: False Positives

**Symptoms**:
- ZAP reports vulnerabilities that don't exist

**Solutions**:
1. **Manually verify**:
   - Test the finding yourself
   - Use Request Editor to reproduce
2. **Check confidence level**:
   - Low confidence = likely false positive
   - High confidence = more reliable
3. **Update ZAP**:
   - Newer versions have improved detection
   - Help → Check for Updates

### Issue 4: Missing Vulnerabilities

**Symptoms**:
- ZAP doesn't find known vulnerabilities

**Solutions**:
1. **Increase scan intensity**:
   - Threshold: High
   - Strength: Medium or High
2. **Manual testing**:
   - Some vulnerabilities require manual testing
   - Use ZAP as proxy, test manually
3. **Check authentication**:
   - Ensure ZAP is testing authenticated pages
   - Verify session is valid

### Issue 5: High CPU/Memory Usage

**Symptoms**:
- ZAP slows down computer
- System becomes unresponsive

**Solutions**:
1. **Increase Java heap**:
   ```bash
   zap.sh -Xmx4g  # 4GB heap
   ```
2. **Reduce scan threads**:
   - Tools → Options → Active Scan
   - Threads per host: 2 (default is 2-4)
3. **Limit scope**:
   - Don't scan entire site if not needed
   - Focus on specific functionality

### Issue 6: Can't Connect to ZAP API

**Symptoms**:
```
curl: (7) Failed to connect to localhost port 8080
```

**Solutions**:
1. **Enable API**:
   - Tools → Options → API
   - Enable the API
   - Note the API key
2. **Check address/port**:
   - Default: localhost:8080
   - Verify in Tools → Options → Local Proxies
3. **Include API key**:
   ```bash
   curl "http://localhost:8080/JSON/core/view/alerts/?apikey=your-key"
   ```

---

## ✅ Best Practices

### For Learning

1. **Start with automated scan**:
   - Quick overview of vulnerabilities
   - See what ZAP can find automatically

2. **Then explore manually**:
   - Browse the application through ZAP
   - Understand how it works
   - Notice patterns

3. **Active scan selectively**:
   - Don't scan everything always
   - Focus on specific features
   - Learn what each scanner does

4. **Verify findings manually**:
   - Don't trust ZAP blindly
   - Reproduce vulnerabilities yourself
   - Understand why they exist

5. **Compare Red vs Blue**:
   - Scan vulnerable version
   - Scan secure version
   - See what fixes prevent vulnerabilities

### For Professional Testing

1. **Get authorization**:
   - Written permission
   - Defined scope
   - Contact information

2. **Configure appropriately**:
   - Protected Mode (prevents out-of-scope attacks)
   - Reasonable scan intensity
   - Appropriate timing (not during peak hours)

3. **Monitor impact**:
   - Watch application performance
   - Pause if issues occur
   - Coordinate with developers

4. **Document thoroughly**:
   - Generate reports
   - Take screenshots
   - Note timestamps
   - Record steps to reproduce

5. **Validate all findings**:
   - High confidence = likely real
   - Low confidence = needs manual verification
   - Test exploitability

### For SecureBank Practice

1. **Use Protected Mode**:
   - Prevents accidentally attacking other sites
   - Good habit for real assessments

2. **Test systematically**:
   - Spider first (discover)
   - Passive scan (safe checks)
   - Active scan (attack)
   - Manual verification

3. **Compare scanning approaches**:
   - ZAP automated vs. manual Burp testing
   - ZAP vs. SQLMap for SQL injection
   - See strengths/weaknesses of each

4. **Practice reporting**:
   - Generate professional reports
   - Write clear vulnerability descriptions
   - Include reproduction steps

### Security and Ethics

1. **Only scan authorized systems**:
   - SecureBank: ✅ Designed for testing
   - Production sites: ❌ Illegal without permission

2. **Be aware of impact**:
   - Active scans can affect performance
   - Some tests may modify data
   - Use with caution

3. **Report responsibly**:
   - If you find real vulnerabilities
   - Follow responsible disclosure
   - Give time for fixes before public disclosure

4. **Keep ZAP updated**:
   - New vulnerability checks added regularly
   - Bug fixes improve accuracy
   - Help → Check for Updates

---

## 🎓 Conclusion

You've learned how to use OWASP ZAP to:

- ✅ Automatically scan web applications for vulnerabilities
- ✅ Use ZAP as an intercepting proxy for manual testing
- ✅ Find SQL injection vulnerabilities
- ✅ Discover IDOR and access control issues
- ✅ Identify XSS vulnerabilities
- ✅ Test for CSRF, mass assignment, and other flaws
- ✅ Generate professional security reports
- ✅ Use ZAP's API for automation
- ✅ Apply professional security testing practices

### Key Takeaways

**Why ZAP is powerful**:
- Completely free and open-source
- Automated scanning saves huge amounts of time
- Active scanner included (unlike free Burp)
- Easy to learn for beginners
- Professional-grade capabilities

**Why manual testing still matters**:
- Automated scans miss logic flaws
- False positives need verification
- Deep understanding requires hands-on testing
- Some vulnerabilities (race conditions, business logic) need manual approach

**Best approach**: Combine tools
- ZAP for breadth (find many issues quickly)
- Manual testing for depth (understand complex issues)
- SQLMap for SQL injection specialization
- Burp for advanced manual techniques

### Next Steps

1. **Practice more**:
   - Scan all SecureBank endpoints
   - Test Blue Team (verify fixes work)
   - Adjust scan policies and see differences

2. **Learn complementary tools**:
   - Burp Suite (manual testing)
   - SQLMap (SQL injection specialist)
   - Nikto (web server scanner)

3. **Real-world practice**:
   - Join bug bounty programs (HackerOne, Bugcrowd)
   - Practice on intentionally vulnerable apps (DVWA, WebGoat, bWAPP)
   - Contribute to OWASP projects

4. **Get certified**:
   - Certified Ethical Hacker (CEH)
   - Offensive Security Web Expert (OSWE)
   - GIAC Web Application Penetration Tester (GWAPT)

### Additional Resources

- **ZAP Documentation**: [zaproxy.org/docs](https://www.zaproxy.org/docs/)
- **ZAP User Group**: [groups.google.com/group/zaproxy-users](https://groups.google.com/group/zaproxy-users)
- **OWASP Testing Guide**: [owasp.org/www-project-web-security-testing-guide](https://owasp.org/www-project-web-security-testing-guide/)
- **Practice Labs**:
  - OWASP WebGoat
  - DVWA (Damn Vulnerable Web Application)
  - OWASP Juice Shop
- **Video Tutorials**: [YouTube: OWASP ZAP tutorials](https://www.youtube.com/playlist?list=PLF0y3pJM_D9_2gE3TaDmHkZ8g0PtCMfG3)

### Final Words

OWASP ZAP is an incredibly powerful tool that puts enterprise-grade security testing capabilities in everyone's hands for free. Whether you're:

- **A developer** wanting to test your own code
- **A student** learning web security
- **A professional** pentester conducting assessments
- **A security enthusiast** exploring vulnerabilities

ZAP is an essential tool in your arsenal.

**Remember**:
- Use your powers responsibly
- Only test authorized systems
- Report vulnerabilities ethically
- Help make the internet more secure

The OWASP Foundation and ZAP community have given us this amazing free tool. Honor that gift by using it to improve security, not cause harm.

**Happy (Ethical) Scanning! 🔒**

---

**Pro Tip**: The best security professionals don't just run tools - they understand the vulnerabilities deeply. Use ZAP to save time finding issues, but always dig deeper to understand the root cause, impact, and proper fix. That's what separates tool users from security experts.

---

**Contributing to ZAP**:
ZAP is open-source! If you find bugs or want to contribute:
- Report issues: [github.com/zaproxy/zaproxy/issues](https://github.com/zaproxy/zaproxy/issues)
- Contribute code: [github.com/zaproxy/zaproxy](https://github.com/zaproxy/zaproxy)
- Write add-ons: [zaproxy.org/docs/developer](https://www.zaproxy.org/docs/developer/)
