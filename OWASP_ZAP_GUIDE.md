# SecurityForge - OWASP ZAP Integration Guide

## 📌 TABLE OF CONTENTS

1. [Installation & Setup](#installation--setup)
2. [ZAP Interface Overview](#zap-interface-overview)
3. [Baseline Scanning](#baseline-scanning)
4. [Active Scanning](#active-scanning)
5. [AJAX Scanner](#ajax-spider-scanning)
6. [API Scanning](#api-scanning-mode)
7. [Script-Based Scanning](#script-based-scanning)
8. [Automation Framework](#automation-framework)
9. [Custom Rules](#custom-detection-rules)
10. [Report Generation](#report-generation)
11. [CI/CD Integration](#cicd-integration-github-actions)
12. [Advanced Techniques](#advanced-techniques)

---

## 🛠️ INSTALLATION & SETUP

### **Step 1: Download OWASP ZAP**

```
1. Visit: https://www.zaproxy.org/download/
2. Download for your OS (Windows/Mac/Linux)
3. Install and launch
4. (Optional) Create account for online update checks
```

### **Step 2: Configure Proxy**

```
ZAP Menu → Tools → Options → Network:

Local Servers/Proxies:
  1. Main Proxy:
     - Address: 127.0.0.1
     - Port: 8080
     - Enable "Decode requests and responses"

2. API Key:
   - Tools → Options → API
   - Generate API key (for automation)
```

### **Step 3: Add Target Application**

```
1. Quick Start → Automated scan
2. Enter URL: http://localhost:5000/api
3. Click "Attack"
           ↓
4. ZAP crawls endpoints and performs active scan
```

---

## 🔍 ZAP INTERFACE OVERVIEW

### **Key Areas Explained**

| Area | Purpose | Usage |
|------|---------|-------|
| **Toolbar** | Quick actions | New scan, pause, resume, stop |
| **Sites Tree** (Left) | Application structure | Shows all discovered endpoints |
| **Request/Response** (Top right) | View HTTP details | Inspect requests and responses |
| **Alerts / Passive** (Bottom) | Vulnerability listing | Review findings |
| **HUD** | Heads-up display | Floating overlay for browser |

---

## 🔓 BASELINE SCANNING

### **Step 1: Baseline Scan (No Active Fuzzing)**

```
ZAP Menu → Quick Start:

1. URL to scan: http://localhost:5000/api
2. Attack mode: "Traditional"
3. Options:
   - Enable "Spider"
   - Disable "Active Scanner" (for baseline only)

Click "Attack"

Process:
  1. ZAP spiders site (crawls all links)
  2. Performs passive scanning (no payload injection)
  3. Reports findings
```

### **Step 2: Analysis Results**

```
Results appear in:
  1. Alerts tab (bottom):
     🔴 High: SQL injection possible in /api/search
     🟡 Medium: Cookie without HttpOnly flag
     🟡 Medium: Missing CSRF tokens
     🟢 Low: Information disclosure in headers

2. Report:
   - Click "View" → HTML Report
   - Shows all findings with details
```

---

## 🎯 ACTIVE SCANNING

### **Method 1: Full Active Scan**

```
ZAP Menu → Quick Start:

1. URL: http://localhost:5000/api
2. Attack mode: "Traditional"
3. Click "Attack"

Configuration:
 - Spider: Enabled (crawl endpoints)
 - Active Scanner: Enabled (test each endpoint)
 - Fuzzer: Enabled (fuzz parameters)

This performs:
  ✅ SQLi testing
  ✅ XSS testing
  ✅ BOLA testing
  ✅ SSRF testing
  ✅ XXE testing
  ✅ Command injection
  ✅ LDAP injection
  ✅ IDOR testing
```

---

### **Method 2: Targeted Active Scan**

```
1. Sites tree (left panel)
   Click on: /api/search

2. Right-click → "Active scan this node"

3. Configure:
   - Attack strength: INSANE
   - Alert threshold: LOW
   - Recurse: Yes

ZAP scans ONLY this endpoint with all payloads
```

---

### **Method 3: Scan with Custom Policy**

```
ZAP Menu → Policies → Manage policies:

1. Click "Scan Policy Manager"
2. Create new policy: "SecurityForge-Full"
3. Configure:
   - Active scanner options
   - Script options
   - Plugin options

4. Enable plugins:
   ✅ SQL Injection
   ✅ XSS
   ✅ SSRF
   ✅ XXE
   ✅ Command Injection
   ✅ BOLA (custom)
   ✅ Rate limiting bypass

5. Set alert thresholds:
   SQL Injection: HIGH → MEDIUM
   XSS: MEDIUM → LOW
```

---

## 🕷️ AJAX SPIDER SCANNING

### **Step 1: Enable AJAX Spider**

```
ZAP Menu → Options → Passive Scan:

Network handling:
  - Enable "Use AJAX Handler" if dashboard uses JS
  
Then:
  1. Sites tree → /dashboard
  2. Right-click → "AJAX Spider"
  3. ZAP uses headless browser to interact with JavaScript
  4. Discovers dynamic content hidden from normal crawler
```

---

## 📊 API SCANNING MODE

### **Step 1: Import API Definition**

```
ZAP Menu → Import file → Import OpenAPI:

1. File type: "OpenAPI 3.0 / Swagger 2.0"
2. Select: securityforge-api.yaml (or .json)
3. ZAP creates API site tree:
     ├── GET /api/vulnerabilities
     ├── POST /api/auth/login
     ├── GET /api/users/{id}
     ├── PATCH /api/users/{id}
     ├── POST /api/orders
     ├── GET /api/orders/{id}
     ├── POST /api/fetch-resource  ← SSRF
     └── etc.
```

### **Step 2: API Scanning**

```
1. Sites tree → /api
2. Right-click → "Active scan"
3. Configuration:
   - Request body scanning: ENABLED
   - Header scanning: ENABLED
   - Cookie scanning: ENABLED
   
ZAP tests:
  ✅ All parameters (path, query, body, header)
  ✅ All accepted content types (JSON, XML, form)
  ✅ Authentication requirements
  ✅ Response codes
```

---

## 💻 SCRIPT-BASED SCANNING

### **Create Custom JavaScript Rules**

```
ZAP Menu → Scripts → Add script:

1. Name: "SecurityForge-BOLA-Detection"
2. Type: "Active scan rule"
3. Engine: "JavaScript" (or Python)
4. Code:

```javascript
function scan(ps, msg, src) {
    // ps = PolicyScriptParameters
    // msg = HttpMessage
    // src = SourceIdentifier
    
    var url = msg.getRequestHeader().getURI().toString();
    
    // Test BOLA on user endpoints
    if (url.includes("/api/users/")) {
        // Try different user IDs
        var userIds = ["1", "2", "3", "999"];
        
        for (var i = 0; i < userIds.length; i++) {
            var testUrl = url.replace(/\/api\/users\/\d+/, "/api/users/" + userIds[i]);
            
            var newMsg = msg.cloneAll();
            newMsg.getRequestHeader().setURI(testUrl);
            
            ps.sendMessage(newMsg);
            
            // check response
            if (newMsg.getResponseHeader().getStatusCode() == 200) {
                // Check if data belongs to different user
                var resp = newMsg.getResponseBody().toString();
                if (resp.includes("user_id") && !resp.includes(userIds[0])) {
                    // BOLA found!
                    ps.raiseAlert(
                        40,  // Risk
                        40,  // Confidence
                        "BOLA Detected",
                        "Different user data accessible",
                        testUrl,
                        "",
                        "",
                        resp,
                        "Add ownership checks",
                        msg
                    );
                }
            }
        }
    }
}
```
```

---

## 🤖 AUTOMATION FRAMEWORK

### **Method 1: Command-Line Scanning**

```bash
# Basic scan
zaproxy -cmd -quickurl http://localhost:5000/api \
  -quickout report.html

# Full scan with options
zaproxy -cmd \
  -url http://localhost:5000/api \
  -config api.disableallscan=false.api.apikey=YOUR_API_KEY \
  -generaterport report.html
```

---

### **Method 2: Script Running**

```bash
# Run automation script
zaproxy -script path/to/automation.yaml

# automation.yaml content:
env:
  contexts:
    - name: SecurityForge
      urls:
        - http://localhost:5000/api

jobs:
  - type: spider
    parameters:
      url: http://localhost:5000/api
      maxChildren: 0
      threads: 5
  
  - type: activeScan
    parameters:
      url: http://localhost:5000/api
      scanPolicyName: "SecurityForge-Full"
      attackStrength: "INSANE"
      alertThreshold: "LOW"
  
  - type: report
    parameters:
      template: "traditional-html-plus"
      reportFile: "/tmp/report.html"
```

---

## 🔧 CUSTOM DETECTION RULES

### **Add Custom Alert Rules**

```
ZAP Menu → Options → Alert rules → Manage alert rules:

Add rule: "SecurityForge-SQLi-Custom"
  Condition: 
    - Response contains: "Syntax error" OR "MySQL" OR "ORA-"
    - AND response code not 5xx
  
  Alert:
    - Risk: High
    - Confidence: Medium
    - Title: "SQLi via error message"
```

---

## 📋 REPORT GENERATION

### **Generate Report**

```
Reports → Generate report:

Options:
  1. Template: "Traditional HTML"
  2. Include:
     ✅ Request/response
     ✅ Evidence
     ✅ Remediation
     ✅ CVSS scoring
  
3. Export as:
   - HTML (view in browser)
   - PDF (for management)
   - Markdown (for documentation)
```

---

## 🔄 CI/CD INTEGRATION (GitHub Actions)

### **Automated Scanning on Commits**

```yaml
name: SecurityForge ZAP Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  zap-scan:
    runs-on: ubuntu-latest
    
    services:
      securityforge:
        image: securityforge:latest
        ports:
          - 5000:5000
        env:
          FLASK_ENV: testing

    steps:
      - uses: actions/checkout@v2
      
      - name: Wait for service
        run: sleep 10
      
      - name: Run ZAP Baseline
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:5000/api'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
      
      - name: Run ZAP Full Scan
        uses: zaproxy/action-full-scan@v0.7.0
        with:
          target: 'http://localhost:5000/api'
          rules_file_name: '.zap/rules.tsv'
      
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v2
        with:
          name: zap-report
          path: report_md.md
```

---

## 🎯 ADVANCED TECHNIQUES

### **Authentication Context Setup**

```
ZAP Menu → Options → Authentication:

1. Create HTTP Session Authentication:
   - Hostname: localhost
   - Port: 5000
   - Login URL: /api/auth/login
   - Username: admin@securityforge.com
   - Password: AdminPassword123

2. Verification URL: /api/admin/users
   (URL that requires authentication)

3. When scanner requests protected endpoints:
   - ZAP automatically authenticates
   - Uses session/token for all requests
```

---

### **Multi-User Testing**

```
Duplicate scanning context for different roles:

1. "SecurityForge-Admin": Login as admin
2. "SecurityForge-Instructor": Login as instructor  
3. "SecurityForge-Student": Login as student

For each context:
   - Run active scan
   - Compare results
   - Identify privilege escalation
```

---

### **Out-of-Band Detection (SSRF/XXE/RCE)**

```
ZAP → Options → OAST Data:

1. Configure Burp Collaborator (or alternative):
   - API key: [from Collaborator]

2. Payloads automatically include Collaborator URLs:
   - http://attacker.oast.pro
   - xxe.oast.pro/file
   - ssrf.oast.pro/metadata

3. ZAP detects callback hits = confirmed SSRF/XXE
```

---

## 📋 TESTING CHECKLIST

- [ ] Baseline scan (passive)
- [ ] AJAX spider (for dynamic content)
- [ ] Active scan (all endpoints)
- [ ] API scan (if using OpenAPI)
- [ ] Custom policy scan
- [ ] Authentication testing
- [ ] Multi-user role testing
- [ ] Out-of-band detection
- [ ] Generate report
- [ ] Export findings

---

**Next: → See FFUF_GUIDE.md for fuzzing endpoints**

