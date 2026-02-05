# ⚡ Quick Start: Backend + Dashboard + Postman Integration

## 30-Second Setup

You have **3 open windows** - follow this checklist:

### Terminal 1: Start the Vulnerable API

```powershell
cd c:\vuln_api_testing
python .\vulnshop.py
```

**Expected Output:**
```
 * Serving Flask app 'vulnshop'
 * Running on http://0.0.0.0:5000
```

✅ Keep this terminal running. Don't close it.

---

### Terminal 2: Open the Dashboard

```powershell
start file:///c:/vuln_api_testing/Dashboard_Interactive.html
```

Or manually open browser and paste: `file:///c:/vuln_api_testing/Dashboard_Interactive.html`

**What you should see:**
- Header: "🔒 VulnShop API - Interactive Dashboard"
- Status: "API Status: Online ✓" (green indicator)
- Live Backend Data tab: Shows real users, products, orders
- 5 tabs available: Live Data, Postman Guide, Vulnerabilities, Attacks, Teaching Guide

✅ Keep dashboard open in browser.

---

### Terminal 3: Open Postman

```powershell
postman
```

(Or open Postman directly from Start Menu)

**Import Collection & Environment:**

1. Click: **Import**
2. Select: `c:\vuln_api_testing\VulnShop_Collection.json`
3. Click: **Import**
4. Click: **Import** again (for environment)
5. Select: `c:\vuln_api_testing\VulnShop_Environment.json`
6. Click: **Import**

**Verify:**
- Left sidebar shows "VulnShop API Top 10" collection
- Environment dropdown shows "VulnShop - Local Lab"

---

## Testing the Connection (2 minutes)

### Step 1: Setup Database

In Postman:
1. Expand: **00 - Setup**
2. Click: **Reset DB**
3. Click: **Send** button
4. See: Response "Database reset successfully"

✅ Database seeded with test data.

---

### Step 2: Login to Get Token

In Postman:
1. Expand: **01 - Auth**
2. Click: **Login User1**
3. Click: **Send** button
4. In response, you see: `"access_token": "eyJ..."`
5. This token automatically saves to `{{token}}` variable

✅ You're authenticated now.

---

### Step 3: Run Your First Attack Test

In Postman:
1. Expand: **02 - API1 BOLA**
2. Click: **Read other user's order**
3. Click: **Send** button

**What happens:**

**Vulnerable API (vulnshop.py):**
```
Status: 200 OK ❌ [RED X]
Response Body: Full order details (You can see User2's order!)
Test Result: FAIL (as expected - this proves vulnerability)
```

✅ **Congratulations!** You've exploited your first API vulnerability!

---

## Trying All 19 Tests

Now you can run through the collection:

```
00 - Setup
  └─ Reset DB

01 - Auth
  └─ Login User1
  └─ Login User2

02 - API1 BOLA (Broken Object Level Authorization)
  ├─ Read other user's order (2 tests)
  └─ Read other user's profile

03 - API2 Authentication
  ├─ Missing token rejection
  └─ Tampered token acceptance

04 - API3 Property Level Authorization
  ├─ Mass assignment - Become admin
  └─ Password exposed in response

05 - API4 Resource Consumption
  └─ Huge pagination limit

06 - API5 Function Level Authorization
  ├─ Admin endpoint accessible to normal user
  └─ Delete product without role check

07 - API6 Business Flows
  └─ Confirm order without paying

08 - API7 SSRF
  └─ Fetch internal localhost

09 - API8 Security Misconfiguration
  └─ CORS wide open

10 - API9 Improper Inventory
  └─ Old debug endpoint exposed

11 - API10 Unsafe Consumption
  └─ Trust third-party API response
```

**Expected Results (Vulnerable Version):**
- ~17 tests show ❌ RED (FAIL) - You exploited them!
- ~2 tests show ✅ GREEN (PASS)
- This proves the API IS vulnerable

---

## Now Test the Secure Version

### Step 1: Stop Vulnerable API

In Terminal 1:
```
Press: Ctrl+C
```

The API will stop. Dashboard will show "Offline ✗".

---

### Step 2: Start Secure API

Still in Terminal 1:
```powershell
python .\secure_vulnshop.py
```

**Expected Output:**
```
 * Running on http://0.0.0.0:5000
```

Wait 2 seconds... Dashboard auto-updates to "Online ✓" again.

---

### Step 3: Run Same Tests Again

In Postman:
1. Click: **01 - Auth → Login User1** (get new token for secure version)
2. Run the 19 tests again

**Expected Results (Secure Version):**
- ~19 tests show ✅ GREEN (PASS)
- Tests that were FAIL are now PASS
- Tests that were PASS stay PASS
- **This proves the fixes work!**

---

## Understanding Test Results

### Green ✅ = PASS = What We Want

```
✅ PASS on VULNERABLE version means:
   Security was not breached in this specific test
   (Some tests pass even on vulnerable API)

✅ PASS on SECURE version means:
   Security control is working correctly
   (This is what production should do)
```

### Red ❌ = FAIL = Vulnerability Confirmed

```
❌ FAIL on VULNERABLE version means:
   A real vulnerability was exploited
   (This is bad!)

❌ FAIL on SECURE version means:
   Something went wrong - check your API
   (This should never happen if code is correct)
```

---

## Dashboard Tabs Explained

### Tab 1: Live Backend Data

What shows here:
- ✓ Real users from database (user1, user2, admin)
- ✓ Real products (Laptop, Headphones, Phone)
- ✓ Real orders that exist
- ✓ Database connection status

Use this to understand what data is being targeted by attacks.

---

### Tab 2: Postman Test Guide

What shows here:
- ✓ Description of each test
- ✓ What the attack is trying to do
- ✓ Expected results (vulnerable vs secure)
- ✓ Security impact

Use this BEFORE running each test to understand what you're testing.

---

### Tab 3: OWASP Vulnerabilities

What shows here:
- ✓ All 10 vulnerabilities in one table
- ✓ Affected endpoints
- ✓ How each one is fixed

Use this as a reference while reviewing code.

---

### Tab 4: Attack Demonstrations

What shows here:
- ✓ Step-by-step walkthroughs of 6 real attacks
- ✓ Exact code/payloads to send
- ✓ Expected results

Use this when you want to show someone else a specific attack.

---

### Tab 5: Teaching Guide

What shows here:
- ✓ 60-minute lesson plan
- ✓ How to present this to students
- ✓ Script for demo
- ✓ Troubleshooting tips
- ✓ Classroom exercises

Use this if you're teaching others about the lab.

---

## Generate a Report

After running all tests, generate documentation:

### In Terminal 2 (or new terminal):

```powershell
cd c:\vuln_api_testing
python .\generate_report.py
```

**Output:**
```
================================================================================
                 VulnShop API - OWASP Top 10 (2023) Test Report
================================================================================

📊 VULNERABILITY SUMMARY
[All 10 APIs listed with status]

📋 DETAILED VULNERABILITY BREAKDOWN
[Each API with description and fix]

🧪 TEST CASE MATRIX
[All 19 tests with results]

📊 Total Tests: 19
⚖️ VULNERABLE vs SECURE COMPARISON
[Side-by-side comparison]

✅ Report exported to vulnshop_report.json
```

---

## Common Commands Reference

```powershell
# Start vulnerable API
python .\vulnshop.py

# Start secure API
python .\secure_vulnshop.py

# Generate test report
python .\generate_report.py

# Open dashboard in browser
start file:///c:/vuln_api_testing/Dashboard_Interactive.html

# View generated report as JSON in PowerShell
Get-Content vulnshop_report.json | ConvertFrom-Json | Out-Host

# Check if API is running
Invoke-WebRequest http://localhost:5000/api/health
```

---

## Success Checklist

- [ ] API running on port 5000 (green indicator in dashboard)
- [ ] Dashboard shows "Online ✓"
- [ ] Live Backend Data tab shows 3 users/products/orders
- [ ] Postman tests run successfully
- [ ] Vulnerable version: ~17 RED, ~2 GREEN
- [ ] Secure version: ~19 GREEN (all pass)
- [ ] Report generates without errors
- [ ] You've read at least one attack explanation in dashboard

✅ If all checked: **You're ready to teach or present!**

---

## Next Steps

### For a 5-Minute Demo:
1. Open dashboard
2. Show "Live Backend Data" tab (real data connected)
3. Run 1 Postman test (BOLA)
4. Show status 200 (vulnerable)
5. Switch to secure version
6. Run same test
7. Show status 403 (fixed)
8. Explain: "Same attack, different code, different result"

### For a 30-Minute Demo:
1. Run entire Postman collection (vulnerable)
2. Show report
3. Switch to secure version
4. Run tests again
5. Explain each vulnerability from dashboard tabs

### For a 60-Minute Class:
Follow the "Teaching Guide" section in dashboard Teaching Guide tab.

---

## File Reference

```
c:\vuln_api_testing\
├── Dashboard_Interactive.html     ← Open this in browser (LIVE CONNECTION)
├── VulnShop_Collection.json       ← Import into Postman
├── VulnShop_Environment.json      ← Import into Postman
├── vulnshop.py                    ← VULNERABLE version (python ./vulnshop.py)
├── secure_vulnshop.py             ← SECURE version (python ./secure_vulnshop.py)
├── generate_report.py             ← Run to generate test report
├── TEACHING_POSTMAN_INTEGRATION.md ← Full teaching guide (THIS FILE)
├── README.md                      ← Setup guide
├── QUICK_REFERENCE.md             ← Cheat sheet
└── vulnshop_report.json           ← Generated test report
```

---

**You're ready! Open your browser and dashboard now, and explore. 🚀**
