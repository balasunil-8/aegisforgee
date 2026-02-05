# VulnShop API - Complete Lab Setup Guide

## 🚀 Quick Start (3 Steps)

### Step 1: Start the API Server
```powershell
cd c:\vuln_api_testing
python .\vulnshop.py
```

You should see:
```
* Running on http://127.0.0.1:5000
* Running on http://192.168.1.7:5000
```

### Step 2: Open the Dashboard
While the API is running, open in your browser:

**Option A - Local:**
```
file:///c:\vuln_api_testing\Dashboard.html
```

**Option B - Drag & Drop:**
1. Open Windows Explorer
2. Navigate to `c:\vuln_api_testing`
3. Drag `Dashboard.html` into your browser

### Step 3: View Live API Status
The dashboard will automatically detect if your API is running and show:
- ✓ API Health Status (online/offline)
- ✓ All 10 OWASP API vulnerabilities 
- ✓ 15+ endpoints with descriptions
- ✓ 19 Postman test cases mapped to each vulnerability
- ✓ Real attack scenarios

---

## 📊 Dashboard Features

### Tab 1: OWASP Alignment
Shows all 10 API vulnerabilities with their test results:

```
API1  │ BOLA                          │ FAIL (vulnerable) │ PASS (fixed)
API2  │ Broken Authentication         │ FAIL              │ PASS
API3  │ Broken Property-Level Auth    │ FAIL              │ PASS
...
API10 │ Unsafe Consumption of APIs    │ FAIL              │ PASS
```

### Tab 2: API Endpoints
Lists all 15+ endpoints with vulnerability mapping:

```
GET /api/users/<id>           → API1 BOLA (no ownership check)
PATCH /api/users/<id>         → API3 Property (mass assignment)
DELETE /api/products/<id>     → API5 Function (no role check)
POST /api/orders/<id>/confirm → API6 Business Logic (no PAID check)
...
```

### Tab 3: Test Cases
Shows all 19 Postman tests organized by vulnerability:

```
✗ API1 - BOLA (2 tests)
  • Read other user's order        
  • Read other user's profile     

✗ API2 - Authentication (3 tests)
  • Missing token accepted        
  • Tampered token accepted       
  • Token restoration            

... (and so on)
```

### Tab 4: Attack Scenarios
Real, exploitable attack steps with expected results:

```
🎯 Attack 1: BOLA - Read Someone Else's Data
   1️⃣ Login as User1 → get JWT
   2️⃣ Send GET /api/orders/2 (belongs to User2)
   Vulnerable: 200 OK + order data (BAD)
   Secure: 403 Forbidden (GOOD)

🎯 Attack 2: Mass Assignment - Become Admin
   1️⃣ Login as User1 (normal user)
   2️⃣ PATCH /users/1 with {"is_admin": true}
   Vulnerable: User becomes admin (BAD)
   Secure: Fields ignored, stays normal (GOOD)
```

---

## 📋 Generate Test Report

Run the report generator to print a comprehensive analysis:

```powershell
cd c:\vuln_api_testing
python .\generate_report.py
```

Output includes:
```
📊 VULNERABILITY SUMMARY
API1 BOLA (Broken Object Level Authorization)    🔴 VULNERABLE
API2 Broken Authentication                        🔴 VULNERABLE
...

🧪 TEST CASE MATRIX
API1: BOLA
  • Test 1: BOLA - Read other user's order
    Attack: Login as User1, read order_id=2 (belongs to User2)
    Vulnerable Result: 200 OK + order data
    Secure Result: 403 Forbidden
    Severity: CRITICAL

🔗 ENDPOINT REFERENCE GUIDE
GET    /api/users/<id>              API1,API3  🔴 Vulnerable
DELETE /api/products/<id>           API5       🔴 Vulnerable

👤 SEEDED TEST ACCOUNTS
user1@example.com   Password123   user
user2@example.com   Password123   user
admin@example.com   Admin123      admin

... plus much more
```

Also exports: `vulnshop_report.json`

---

## 🧪 Using with Postman

### Import Collections
1. Open Postman
2. Click **Import**
3. Upload `VulnShop_Collection.json`
4. Upload `VulnShop_Environment.json`
5. Select Environment: **VulnShop - Local Lab**

### Run Tests
**Option A - Manual (Best for Learning):**
1. Go to folder "01 - Auth"
2. Run "Login User1" (saves JWT token)
3. Go to folder "02 - API1 BOLA"
4. Run "Read other user's order"
5. See Response: 200 + data (VULNERABLE!)
6. Read test script to understand results
7. Continue through all 10 folders

**Option B - Collection Runner (Batch Results):**
1. Collections → VulnShop API Top 10
2. Click **Run**
3. Select Environment: VulnShop - Local Lab
4. Click **Run VulnShop API Top 10**
5. See test results (green ✓ or red ✗)

---

## 🔄 Attack → Patch → Verify Workflow

### Phase 1: Attack (Show Vulnerabilities)
```powershell
# Terminal 1: Run vulnerable API
python .\vulnshop.py
```

```
# Terminal 2: Run Postman tests
Open Dashboard.html → See all tests FAIL (red ✗)
```

### Phase 2: Learn (Understand Fixes)
1. Read code comments in `vulnshop.py` showing WHY each is vulnerable
2. Compare with `secure_vulnshop.py` to see the fixes
3. Note the differences in:
   - Ownership checks
   - Role-based access control
   - Input validation
   - State machine enforcement

### Phase 3: Patch (Switch to Secure)
```powershell
# Stop vulnerable API (Ctrl+C)

# Start secure API
python .\secure_vulnshop.py
```

### Phase 4: Verify (Show Fixes Work)
```
Rerun all Postman tests → See most tests PASS (green ✓)
```

---

## 🎓 60-Minute Classroom Lesson Plan

| Time | Activity | Materials |
|------|----------|-----------|
| 5 min | Setup | Start API, open Dashboard |
| 10 min | Overview | Show Dashboard tabs, explain OWASP Top 10 |
| 20 min | Demonstrate Attacks | Run Postman tests, explain each vulnerability |
| 10 min | Code Review | Show vulnshop.py code, explain flaws |
| 10 min | Patch & Verify | Switch to secure_vulnshop.py, re-run tests |
| 5 min | Q&A | Students ask questions |

---

## 📁 File Structure

```
c:\vuln_api_testing\
├── vulnshop.py                    ← Vulnerable API (for attacks)
├── secure_vulnshop.py             ← Patched API (for verification)
├── requirements.txt               ← Python dependencies
├── Dashboard.html                 ← 📊 VISUAL DASHBOARD (open in browser)
├── generate_report.py             ← 📋 TEST REPORT GENERATOR
├── VulnShop_Collection.json       ← Postman collection
├── VulnShop_Environment.json      ← Postman environment
├── README.md                      ← Full documentation
├── POSTMAN_TESTING_GUIDE.md      ← How to use Postman
├── QUICK_REFERENCE.md            ← One-page cheat sheet
└── .venv/                         ← Virtual environment (after setup)
```

---

## How to Display Everything

### To Students/Stakeholders:

```
1. On Your Machine (Instructor):
   • Terminal: python .\vulnshop.py (API running)
   • Browser: Dashboard.html (live status, counts, tables)
   • Postman: VulnShop_Collection.json (running tests)

2. Projected Display:
   • Dashboard showing OWASP vulnerability matrix
   • Postman running the test suite
   • Live results showing FAIL/PASS

3. Downloadable Report:
   • python .\generate_report.py  (generates report.pdf/html/json)
   • Students get: Full analysis + all attack scenarios + fixes
```

### Dashboard Displays:

- **Statistics Box**: 10 Vulnerabilities, 15+ Endpoints, 19 Tests, 3 Accounts
- **OWASP Matrix**: All 10 APIs with their vulnerable vs secure results
- **Endpoint Reference**: Complete list of all API endpoints with vulnerability mappings
- **Test Cases**: All 19 Postman tests organized by category
- **Attack Scenarios**: 6 real attack chains with steps and expected results
- **Live Status**: API health indicator (shows online/offline with pulse animation)

---

## Quick Commands Reference

```powershell
# Setup
cd c:\vuln_api_testing
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt

# Run vulnerable API
python .\vulnshop.py

# Run secure API
python .\secure_vulnshop.py

# Generate test report
python .\generate_report.py

# Open dashboard (in browser)
# file:///c:\vuln_api_testing\Dashboard.html

# Check if API is running
curl http://localhost:5000/api/health
```

---

## Expected Test Results

### With `vulnshop.py` (Vulnerable):
```
POSTMAN TEST RESULTS (Vulnerable)
════════════════════════════════════
✓ 00 - Setup                    (2 PASS)
✓ 01 - Auth                     (4 PASS)
✗ 02 - API1 BOLA               (2 FAIL) - Cross-user access allowed
✗ 03 - API2 Auth               (3 FAIL) - Missing/bad tokens accepted
✗ 04 - API3 Property           (2 FAIL) - Mass assignment works
✗ 05 - API4 Resource           (1 FAIL) - Huge limit accepted
✗ 06 - API5 Function           (2 FAIL) - Admin functions accessible
✗ 07 - API6 Business           (2 FAIL) - Confirm without payment
✗ 08 - API7 SSRF              (1 FAIL) - Internal URLs fetched
✗ 09 - API8 Misconfig         (1 FAIL) - CORS allows *
✗ 10 - API9 Inventory         (1 FAIL) - Debug endpoint exposed
✗ 11 - API10 Unsafe           (2 FAIL) - Provider trusted blindly

TOTAL: 17 FAIL, 2 PASS (Expected for vulnerable API)
```

### With `secure_vulnshop.py` (Secure):
```
POSTMAN TEST RESULTS (Secure)
════════════════════════════════════
✓ 00 - Setup                    (2 PASS)
✓ 01 - Auth                     (4 PASS)
✓ 02 - API1 BOLA               (2 PASS) - Cross-user access blocked
✓ 03 - API2 Auth               (3 PASS) - Bad tokens rejected
✓ 04 - API3 Property           (2 PASS) - Fields ignored
✓ 05 - API4 Resource           (1 PASS) - Limit capped at 100
✓ 06 - API5 Function           (2 PASS) - Admin check enforced
✓ 07 - API6 Business           (2 PASS) - Payment enforcement
✓ 08 - API7 SSRF              (1 PASS) - Internal IPs blocked
✓ 09 - API8 Misconfig         (1 PASS) - CORS restricted
✓ 10 - API9 Inventory         (1 PASS) - Endpoint removed
✓ 11 - API10 Unsafe           (2 PASS) - Provider allowlisted

TOTAL: 19 PASS, 0 FAIL (Secure API passes all tests)
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Dashboard shows "Offline" | Make sure `python .\vulnshop.py` is running in terminal |
| Postman token not saving | Run "Login User1" first, wait for response, check environment |
| Port 5000 in use | `netstat -ano \| findstr :5000` then `taskkill /PID <PID> /F` |
| Python module errors | `pip install -r requirements.txt` |
| Can't open Dashboard.html | Copy full path: `file:///c:/vuln_api_testing/Dashboard.html` |

---

## For Your Teaching

Print this page and give to students:

- Dashboard link
- Postman collection link
- Test account credentials
- Expected results table
- Quick attack scenarios (copy-paste ready)

Students can then:
1. Run Postman tests
2. See vulnerabilities in action
3. Read code to understand WHY
4. Compare with secure version
5. Verify fixes work

---

**You're now ready to teach OWASP API Top 10 hands-on! 🎓**
