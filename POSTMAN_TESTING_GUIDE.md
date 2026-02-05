# VulnShop Postman Testing Guide

## How to Run Tests

### Option 1: Manual Testing (Recommended for Learning)

1. **Import files into Postman:**
   - Postman → Import → VulnShop_Collection.json
   - Postman → Import → VulnShop_Environment.json

2. **Select environment:**
   - Top right: select "VulnShop - Local Lab"

3. **Run requests in order:**
   - 00 - Setup → Reset DB
   - 01 - Auth → Login User1 (saves tokens)
   - 02 - API1 → BOLA tests
   - 03 - API2 → Auth tests
   - Continue through API10

### Option 2: Collection Runner (Batch Testing)

1. **Open Collection Runner:**
   - Postman → Collections → VulnShop API Top 10
   - Click "Run" (play icon)

2. **Configure:**
   - Environment: "VulnShop - Local Lab"
   - Iterations: 1
   - Delay: 100ms (between requests)

3. **Click "Run VulnShop API Top 10"**

4. **View Results:**
   - Green checkmarks = tests passed (secure API)
   - Red X = tests failed (vulnerable API)

---

## Expected Test Results

### Running Against vulnshop.py (Vulnerable)

You'll see mostly red X (vulnerable behaviors):

```
✓ 00 - Setup
  ✓ Reset DB returns 200

✓ 01 - Auth
  ✓ Login User1
  ✓ Login User2

✗ 02 - API1 BOLA
  ✗ FAIL: server allowed cross-user order access (should be PASS)
  ✗ FAIL: server allowed cross-user profile access

✗ 03 - API2 Auth
  ✗ FAIL: missing token was accepted (should reject)

✗ 04 - API3 Property
  ✗ FAIL: user could change is_admin (mass assignment)
  ✗ FAIL: password exposed in response

✗ 05 - API4 Resource
  ✗ FAIL: server accepted huge limit

✗ 06 - API5 Function
  ✗ FAIL: admin function accessible to normal user
  ✗ FAIL: delete allowed without role check

✗ 07 - API6 Business
  ✗ FAIL: confirm works without payment

✗ 08 - API7 SSRF
  ✗ FAIL: SSRF allowed internal fetch

✗ 09 - API8 Misconfig
  ✗ FAIL: CORS allows *

✗ 10 - API9 Inventory
  ✗ FAIL: old debug endpoint exposed

✗ 11 - API10 Unsafe
  ✗ FAIL: server trusted third-party quote

Summary: 2 PASS, 17 FAIL (as expected for vulnerable API)
```

---

### Running Against secure_vulnshop.py (Secure)

Most tests should pass (green ✓):

```
✓ 00 - Setup
  ✓ Reset DB returns 200

✓ 01 - Auth
  ✓ Login User1
  ✓ Login User2

✓ 02 - API1 BOLA
  ✓ PASS: server blocked cross-user order access (403)
  ✓ PASS: server blocked cross-user profile access (403)

✓ 03 - API2 Auth
  ✓ PASS: missing token rejected (401)
  ✓ PASS: tampered token rejected (401)

✓ 04 - API3 Property
  ✓ PASS: property-level changes blocked
  ✓ PASS: password not exposed

✓ 05 - API4 Resource
  ✓ PASS: server rejected huge limit (400)

✓ 06 - API5 Function
  ✓ PASS: admin function blocked (403)
  ✓ PASS: delete restricted (403)

✓ 07 - API6 Business
  ✓ PASS: confirm blocked unless paid (409)

✓ 08 - API7 SSRF
  ✓ PASS: SSRF blocked (403)

✓ 09 - API8 Misconfig
  ✓ PASS: CORS not wide-open

✓ 10 - API9 Inventory
  ✓ PASS: old endpoint protected/removed (404)

✓ 11 - API10 Unsafe
  ✓ PASS: provider response blocked or validated

Summary: 19 PASS, 0 FAIL (secure API passes all tests)
```

---

## Understanding Test Scripts

Each Postman request has a "Tests" tab that runs after the request completes.

### Example: API1 BOLA Test Script

```javascript
// PASS = secure behavior (403). FAIL = vulnerable behavior (200 + data).
if (pm.response.code === 403) {
  pm.test('PASS (secure): server blocked cross-user order access (403)', () => true);
} else {
  pm.test('FAIL (vulnerable): server allowed cross-user order access', () => false);
  pm.environment.set('API1_BOLA', 'VULNERABLE');
}
```

**Translation:**
- If response status = 403 → Server is **SECURE** (blocked access)
- If response status = 200 → Server is **VULNERABLE** (allowed access)

---

## Manual Testing Without Runner

If you prefer clicking each request individually:

1. **00 - Reset DB**
   ```
   Send POST /api/setup/reset
   Expect: 200 OK
   ```

2. **01 - Login User1**
   ```
   Send POST /api/auth/login with {"email": "user1@example.com", "password": "Password123"}
   Expect: 200 OK + JWT token
   Environment token_user1 is auto-saved
   ```

3. **02 - BOLA Attack**
   ```
   Send GET /api/orders/2 (as User1, but this order belongs to User2)
   Vulnerable result: 200 OK + order data (BAD)
   Secure result: 403 Forbidden (GOOD)
   ```

---

## Creating Your Own Test

### Template

```javascript
// Pre-request Script (runs BEFORE request, can modify request)
pm.environment.set('my_variable', 'some_value');

// Tests (runs AFTER request, validates response)
pm.test('My Test Name', () => {
    pm.response.to.have.status(200);
    pm.response.to.have.jsonBody('user.id', 1);
});
```

### Example: Add a custom SSRF test

```javascript
pm.test('SSRF Attack: Fetch internal IP', () => {
    // Vulnerable: status 200 and body contains content
    // Secure: status 403 or error
    if (pm.response.code === 403) {
        pm.test('PASS: SSRF blocked', () => true);
    } else if (pm.response.code === 200) {
        pm.test('FAIL: SSRF allowed', () => false);
    }
});
```

---

## Tips & Tricks

### View Raw Response
- Postman → Response tab → "Raw" button

### Debug Token
- Copy the JWT token from environment
- Go to https://jwt.io
- Paste token → see decoded payload

### Export Test Results
- Collection Runner → "Export Results" button
- Saves as HTML report

### Save Custom Environment
- Postman → Environments → VulnShop - Local Lab
- Modify variables (e.g., `base_url`)
- Click Save

---

## Classroom Workflow

1. **Prep (5 min):**
   - Start `vulnshop.py`
   - Import collection + environment in Postman

2. **Demo Attack (20 min):**
   - Run "01 - Auth" to get tokens
   - Manually run API1 BOLA test
   - Show response (students see order data fetched across users)
   - Explain the vulnerability

3. **Batch Test (10 min):**
   - Collection Runner → run all tests
   - Show red X marks (vulnerable behaviors)
   - Screenshot for report

4. **Switch to Secure (5 min):**
   - Stop `vulnshop.py`, start `secure_vulnshop.py`
   - Rerun same tests
   - Show green checkmarks (now secure)

5. **Report (5 min):**
   - Export results
   - Students verify "before & after"

---

**Total: 45 minutes of hands-on OWASP API Top 10 learning**
