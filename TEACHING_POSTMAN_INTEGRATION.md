# 🎓 Integrating Dashboard, Postman & Backend - Teaching Guide

## Overview

You now have a complete **3-layer integration** for teaching OWASP API vulnerabilities:

```
┌─────────────────────────────────────────────────────┐
│  PRESENTATION LAYER (Dashboard_Interactive.html)   │
│  - Real-time backend data display                   │
│  - OWASP vulnerability matrix                       │
│  - Postman test explanations                        │
│  - Attack step-by-step walkthroughs                 │
└────────────────────┬────────────────────────────────┘
                     │
                     ├─→ [API Layer] ←──────────┐
                     │   (vulnshop.py)          │
                     │   (secure_vulnshop.py)   │
                     │                          │
┌────────────────────┴─────────────────────────┴──────┐
│  TESTING LAYER (Postman)                            │
│  - 19 pre-built test cases                          │
│  - Automated PASS/FAIL validation                   │
│  - Environment variable management                  │
└─────────────────────────────────────────────────────┘
                     │
┌────────────────────┴──────────────────────────────────┐
│  EDUCATION LAYER (This Document)                     │
│  - Step-by-step teaching scripts                     │
│  - How to explain connections to students           │
│  - 60-minute lesson plan                            │
│  - Demo command sequences                           │
└──────────────────────────────────────────────────────┘
```

---

## Part 1: How the Dashboard Connects to Backend

### Dashboard Architecture

Your `Dashboard_Interactive.html` does this:

1. **On page load** → JavaScript fetches `http://localhost:5000/api/health`
   - If successful → Shows green "Online ✓" badge
   - If failed → Shows red "Offline ✗" badge

2. **When "Live Backend Data" tab opened** → Fetches:
   - `GET /api/users` → Displays all users in a table
   - `GET /api/products` → Shows all products
   - `GET /api/orders` → Lists all orders
   - Updates stat boxes with counts

3. **Every 5 seconds** → Re-checks API health status

### Key Code Section

```javascript
// In Dashboard_Interactive.html
async function checkAPIStatus() {
    try {
        const response = await fetch('http://localhost:5000/api/health', {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (response.ok) {
            // Green indicator + load data
            statusIndicator.className = 'status-indicator online';
            loadBackendData(); // Fetch users, products, orders
        } else {
            // Red indicator
            statusIndicator.className = 'status-indicator offline';
        }
    } catch (error) {
        statusIndicator.className = 'status-indicator offline';
    }
}
```

### What Each Tab Shows

| Tab | Shows | Purpose |
|-----|-------|---------|
| Live Backend Data | Real users, products, orders | Proves API is running with data |
| Postman Test Guide | 19 tests explained step-by-step | How to run each test & what to expect |
| OWASP Vulnerabilities | All 10 APIs with fixes | Reference table for security knowledge |
| Attack Demonstrations | 6 real attacks with steps | Walk through actual exploitation |
| Teaching Guide | 60-min lesson plan | How to teach this to others |

---

## Part 2: Pre-Demo Setup (5 minutes before class)

### Checklist

- [ ] **Terminal 1 Running:** `python .\vulnshop.py` (vulnerable API)
- [ ] **Terminal 2 Ready:** Postman with VulnShop collection imported
- [ ] **Browser Tab 1:** `file:///c:/vuln_api_testing/Dashboard_Interactive.html`
- [ ] **Browser Tab 2:** Postman

### Test the Connection

Before starting demo, verify everything works:

```powershell
# In PowerShell, check if API is accessible
Invoke-WebRequest http://localhost:5000/api/health

# Expected output: StatusCode 200
```

If you get connection refused, restart API:
```powershell
python .\vulnshop.py
```

---

## Part 3: Live Demo Script (60 minutes)

### Minute 0-3: Opening

**Say to class:**

> "Good morning. I'm going to show you how real APIs get hacked. This is VulnShop - a fake e-commerce API that I've intentionally built with all 10 OWASP API vulnerabilities. Over the next hour, you'll see how attackers exploit these flaws, and then how to fix them. Every vulnerability here is real and happens in production. Let's start."

**Show:** Point at your laptop screen showing the dashboard

---

### Minute 3-8: Show Real Data

**Say:**
> "First, let me show you what we're protecting. This dashboard is connected to a real API backend..."

**Do:**
1. Open browser → Dashboard_Interactive.html
2. Show header: API Status shows "Online ✓"
3. Click **"Live Backend Data"** tab
4. Point out the three tables:
   - Users: user1, user2, admin
   - Products: Laptop, Headphones, Phone
   - Orders: 2 sample orders

**Ask class:**
> "Now imagine User1 is a customer. Their order contains their address, what they bought, how much they paid. What if an attacker could see User2's orders? Your company gets sued. What if they see all orders? You lose customer trust."

---

### Minute 8-20: Attack Demonstration - BOLA

**Say:**
> "Let me show you how easy it is to break this API. Watch carefully..."

**Setup (Do in Postman):**
1. Click: **01 - Auth → Login User1**
2. Click: **Send** button
3. Show: Token in response → It's now saved in {{token}} variable
4. Point at dashboard: "Order 2 belongs to User2, but I'm logged in as User1"

**The Attack (Dramatic moment):**
1. Click: **02 - API1 BOLA → Read other user's order**
2. Show the endpoint: `GET /api/orders/2`
3. Click: **Send**
4. Point at response: "Status 200 - I got User2's entire order!"
5. Expand the JSON and show: order details, items, price

**The Lesson:**
```
┌─────────────┐
│   Attacker  │
│  (User 1)   │
└──────┬──────┘
       │
       │ GET /api/orders/2
       │ (with my User1 token)
       ▼
┌─────────────────────┐
│   VulnShop API      │
│  No ownership check │◄─── BUG: Just looks up order by ID
└────────┬────────────┘     and returns it immediately
         │
         │ 200 OK + Order 2 data
         │ (User2's private order!)
         ▼
    [LEAKED DATA]
```

**Ask class:**
> "Does the API check: is User1 allowed to view Order 2? NO. That's the vulnerability. It should say 403 Forbidden."

---

### Minute 20-28: Show the Code Problem

**Open VSCode**

**Vulnerable Code (vulnshop.py):**
```python
@app.route('/api/orders/<int:order_id>', methods=['GET'])
@jwt_required()
def get_order(order_id):
    # BUG: No check if user owns this order!
    order = Order.query.get_or_404(order_id)
    return jsonify(order.to_dict()), 200
```

**Say:**
> "See this? The code just gets the order by ID and returns it. There's ZERO check for: does this user OWN this order?"

**Secure Code (secure_vulnshop.py):**
```python
@app.route('/api/orders/<int:order_id>', methods=['GET'])
@jwt_required()
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    
    # FIX: Verify ownership before returning
    if order.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify(order.to_dict()), 200
```

**Say:**
> "The fix is simple: 3 lines of code. Check if the user requesting owns the order. If not: 403 Forbidden."

---

### Minute 28-35: Vulnerable vs Secure Comparison

**This is the WOW moment.**

**Say:**
> "Now here's the powerful part. Let me stop this vulnerable version and switch to the SECURE one..."

**Do:**
1. In terminal, press **Ctrl+C** to stop `vulnshop.py`
2. Run: `python .\secure_vulnshop.py`
3. Wait for "Running on..." message
4. In browser, dashboard auto-detects it's still "Online ✓"
5. In Postman, click the BOLA test again (exact same test)
6. Click **Send**
7. Show response: **Status 403 Forbidden**

**The Impact:**
```
BEFORE: Status 200 - Attacker reads User2's order ❌
AFTER:  Status 403 - Access denied ✓

SAME ATTACK.
DIFFERENT CODE.
COMPLETELY DIFFERENT OUTCOME.
```

**Ask class:**
> "Which version do you WANT running in production? Obviously the second one. But how many companies run code like version 1?"

---

### Minute 35-45: High-Speed Attack Series

Pick **3 more attacks** to demonstrate rapid-fire:

#### Attack 2: Mass Assignment (Become Admin)

**Terminal Output in Dashboard:**
- Shows User1 is normal user before attack
- After attacking: Now admin!

**Postman:** Run **04 - API3 Property Level Authorization → Become Admin**
- Send: `PATCH /api/users/1` with `{"is_admin": true}`
- Vulnerable: Status 200, you're admin now
- Secure: Status 200 but role not changed

#### Attack 3: Business Logic (Free Shopping)

**Postman sequence:**
1. `POST /api/orders` - Create order
2. `POST /api/orders/{id}/confirm` - Confirm WITHOUT paying
3. Vulnerable: Works! You got free item!
4. Secure: 409 Conflict "Must pay first"

#### Attack 4: DOS via Resource Exhaustion

**Postman:** `GET /api/products?limit=999999`
- Vulnerable: Takes 10 seconds, uses 80% CPU
- Secure: Instant 400 error

---

### Minute 45-52: Dashboard Teaching Aids

**Click through dashboard tabs to reinforce:**

1. **OWASP Vulnerabilities tab** - Show the table
   - Read row API1, API2, API3
   - Point: "10 different ways attackers break APIs"

2. **Attack Demonstrations tab** - Read one scenario
   - Show step-by-step attack workflow
   - Explain: "This is how real hackers work"

3. **Teaching Guide tab** - Show the lessons
   - Point: "Every API problem has a fix"
   - Examples: Ownership checks, pagination caps, role checks

---

### Minute 52-58: Generate & Discuss Report

**In terminal:**
```powershell
python .\generate_report.py
```

**Show the output:**
- Lists all 10 vulnerabilities
- Shows 19 test cases
- Expected test results table
- Recommendations

**Say:**
> "This report documents everything we learned. Your managers can read this. Your security team can use this checklist. This is what PROOF looks like."

---

### Minute 58-60: Q&A & Closing

**Ask class:**

1. "What's the #1 vulnerability you'll look for in your own code?"
2. "When you write APIs, what question should you always ask?"
   - **Answer they should give:** "Do I have permission checks?"
3. "How many knew this before today?"
   - Show of hands, celebrate learning

**Closing Statement:**
> "Write APIs like paranoid people. Assume the person using your API is trying to break it. For every endpoint ask: Am I checking who's asking? Am I checking if they OWN the data? Am I enforcing business logic? If you're not sure, add a check. It's better to block a legitimate request than leak customer data. Thank you."

---

## Part 4: Explaining Individual Test Cases

### For Each Postman Test, Use This Template

#### Test: BOLA - Read Other User's Order

**1. Context (set the stage)**
```
User1 is logged in and wants to view their orders.
An attacker (also User1) wants to view User2's orders.
Both use the same endpoint but different IDs.
```

**2. The Attack (what we're testing)**
```
GET /api/orders/2
Header: Authorization: Bearer {user1_token}

Q: Can User1 view Order 2?
Q: Does the API check ownership?
```

**3. Expected Results**
```
VULNERABLE version:
  Status Code: 200 OK ❌
  Response: Full order with User2's data
  Problem: No permission check!

SECURE version:
  Status Code: 403 Forbidden ✓
  Response: "Access Denied"
  Why: Ownership verified before returning
```

**4. Real-World Impact**
```
Impact Level: CRITICAL
Attacker can:
  • Read every customer's orders
  • See addresses, preferences, spending patterns
  • Identify high-value targets
  • Blackmail customers
Business impact: Data breach, lawsuits, reputation damage
```

**5. The Fix**
```python
# Before each resource access, verify:
if resource.user_id != current_user.id:
    return forbidden()
```

---

### Template for Explaining Mass Assignment

**1. Context**
```
User1 is a normal user with limited permissions.
But can User1 change their own user record?
What if the API accepts all fields blindly?
```

**2. The Attack**
```
PATCH /api/users/1
Body: {"is_admin": true, "role": "admin"}

Q: Does the API filter fields?
Q: Can anyone become admin?
```

**3. Expected Results**
```
VULNERABLE:
  Status: 200 OK
  Response: Your user object now has is_admin = true
  You're now admin! ❌

SECURE:
  Status: 200 OK
  But the field is IGNORED in responses
  You remain normal user ✓
```

**4. The Fix**
```python
# Allowlist safe fields
ALLOWED_FIELDS = ['name', 'email']  # NOT 'is_admin'!

for field in request.json:
    if field in ALLOWED_FIELDS:
        setattr(user, field, request.json[field])
```

---

### Template for Business Logic (Confirm Without Paying)

**1. Context**
```
E-commerce workflow should be:
1. Create order (CREATED state)
2. Pay for order (/pay endpoint)
↓ Balance deducted
3. Confirm order (CONFIRMED state)

Vulnerability: What if we skip step 2?
```

**2. The Attack**
```
POST /api/orders → Create order
POST /api/orders/{id}/confirm → Confirm WITHOUT /pay

Does the API enforce sequence?
```

**3. Expected Results**
```
VULNERABLE:
  Confirm succeeds! Order status: CONFIRMED
  Your balance: NOT deducted
  Free item! ❌

SECURE:
  409 Conflict: "Order must be PAID first"
  Workflow enforced ✓
```

**4. The Fix**
```python
# Enforce state machine
ORDER_STATES = {
    'CREATED': ['PAY'],      # Can only pay
    'PAID': ['CONFIRM'],     # Can only confirm after paid
    'CONFIRMED': ['SHIP'],   # Can only ship after confirmed
}

if next_action not in ORDER_STATES[order.status]:
    return error("Invalid transition")
```

---

## Part 5: Classroom Activities

### Activity 1: Prediction Game (10 minutes)

Before running each test:

**Say to class:**
> "Before I run this test, I want you to predict what will happen. Raise your hand if you think it will:"

**For BOLA test:**
- A) Status 200 - I can see other user's order!
- B) Status 401 - Access Denied
- C) Status 403 - Forbidden

**After predictions, run test and show actual result.**

**Debrief:**
> "Interesting - most guessed B but it was A. This shows why Security by Default is hard. Our intuition says deny access, but developers often forget!"

---

### Activity 2: "Find the Vulnerable Code" (15 minutes)

**In VSCode, show vulnerable code:**

```python
@app.route('/api/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({
        'id': user.id,
        'email': user.email,
        'password': user.password,  # ← Problem 1
        'role': user.role
    }), 200
```

**Ask class:** "Find all the problems"

**Answers:**
1. No ownership check (BOLA)
2. Password exposed (Mass Assignment)
3. Role exposed (could be used for privilege escalation)

**Show secure version - compare line by line**

---

### Activity 3: Fix Challenge (20 minutes)

**Give students this:**

```python
# VULNERABLE - Student task: Fix this code
@app.route('/api/products', methods=['GET'])
def list_products():
    limit = request.args.get('limit', 10)
    products = Product.query.limit(limit).all()
    return jsonify(products), 200
```

**Challenge:**
- "This endpoint has a Resource Exhaustion vulnerability"
- "Rewrite it to be secure"
- Show them the secure version and compare

**Learning:**
- Real security issues = concrete code problems
- Fixes are often simple (1-3 lines)
- Best practices = known patterns to apply

---

### Activity 4: API Audit Assignment (Homework)

**After class:**

**Give students this checklist:**

```markdown
# API Security Checklist

For your company's REST APIs, answer:

[ ] Do all endpoints verify user authentication?
[ ] Do all endpoints check resource ownership?
[ ] Do you allowlist input fields (no blind mass assignment)?
[ ] Do you enforce pagination caps?
[ ] Do you have role-based access control?
[ ] Do you enforce business logic flows?
[ ] Do you block internal IP access?
[ ] Do you disable debug features in production?
[ ] Do you remove old/legacy endpoints?
[ ] Do you validate third-party API responses?

Score: 
- 10/10 = EXCELLENT
- 7-9/10 = GOOD
- 4-6/10 = NEEDS WORK
- <4/10 = CRITICAL RISK
```

**Assignment:**
> "Audit your own code. For each 'NO', write how you'll fix it in the next sprint."

---

## Part 6: Showing to Stakeholders/Managers

If you need to demonstrate to upper management:

### 5-Minute Executive Summary

```
VP/Manager: "Is our API secure?"

YOU: "Let me show you. Here's our API running with sample data.
      I'll demonstrate 3 real vulnerabilities..."

[Run BOLA test]
"Attacker here can read any customer's data."

[Run Mass Assignment]
"Attacker here can make themselves admin."

[Switch to secure version]
"Here's our fixed version. Same attacks, now all blocked."

Message: "For every vulnerability, there's a fix. 
          We've implemented all of them."
```

### 15-Minute Board Presentation

1. **Slide 1:** Show Dashboard → Live data proof
2. **Slide 2:** Demo BOLA attack → Impact explanation
3. **Slide 3:** Fix code comparison
4. **Slide 4:** Generate report metrics
5. **Slide 5:** Recommendations & timeline

---

## Part 7: Troubleshooting Teaching Issues

### Problem: "The dashboard shows Offline"

**Cause:** API crashed or stopped
**Fix:**
```powershell
# Check if running
get-process python

# If not running:
python .\vulnshop.py

# Refresh browser
```

### Problem: "Postman test returns 401 Unauthorized"

**Cause:** No JWT token or token expired
**Fix:**
1. Run: **01 - Auth → Login User1**
2. Verify {{token}} variable is populated in Environment
3. Try test again

### Problem: "I switched to secure_vulnshop.py but Postman fails"

**Cause:** Environment token from vulnerable version may not work
**Fix:**
1. Run Login again in Postman (gets new token)
2. Re-run tests

### Problem: "Results don't match the guide"

**Cause:** Running wrong version or dirty database
**Fix:**
1. Verify running: `python .\vulnshop.py` (vulnerable)
2. Run: **00 - Setup → Reset DB** in Postman
3. Try again

---

## Summary: Teaching Workflow

```
BEFORE CLASS:
  ✓ Verify API running on port 5000
  ✓ Open dashboard_interactive.html
  ✓ Test one Postman test to confirm connection
  ✓ Print handouts

DURING CLASS:
  ✓ 0-5 min: Intro + show dashboard
  ✓ 5-15 min: Live data proof
  ✓ 15-40 min: 3-4 attack demos (Postman)
  ✓ 40-50 min: Show vulnerable vs secure code
  ✓ 50-60 min: Q&A + generate report handout

AFTER CLASS:
  ✓ Email: Dashboard link + generate_report.py output
  ✓ Send: QUICK_REFERENCE.md to students
  ✓ Assign: API security checklist homework
```

---

## Key Teaching Principles

1. **Show Real Data** - Dashboard proves API is connected, not theoretical
2. **Demonstrate Live Attacks** - Postman showing actual 200 vs 403 is compelling
3. **Show the Code** - Link vulnerability → code → fix is educational
4. **Vulnerable THEN Secure** - Students see problem, then solution
5. **Impact First** - Explain real-world consequences of each flaw
6. **Make it Interactive** - Let students run tests, predict outcomes
7. **Provide Checklists** - Give students something to take away and use

Good luck teaching! 🚀
