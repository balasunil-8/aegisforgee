
# SecurityForge - Professional API Security Testing Platform

SecurityForge is a comprehensive API security testing and vulnerability research platform.
Educate yourself on OWASP vulnerabilities with intentionally vulnerable endpoints.

---

## Quick Start (Windows PowerShell)

### Step 1: Setup Python Virtual Environment

```powershell
cd c:\vuln_api_testing

# Create virtual environment
python -m venv .venv

# Activate it
.\.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Run the App (local)

Start the Flask app directly:

```powershell
python pentestlab_api.py
```

Or build & run with Docker (recommended for portability):

```powershell
docker build -t securityforge:local .
docker run -p 5000:5000 --rm securityforge:local
```

Open `http://localhost:5000/api/health` to verify the service.

### Postman / Tooling

Import the provided Postman collection and environment (if present). Use Postman, Burp Suite, or OWASP ZAP against the lab running locally or in a sandboxed container.

---

## Rebrand and Safe Deployment Notes

SecurityForge is intentionally vulnerable for learning. Do not expose a vulnerable instance publicly without sandboxing per-user labs and egress controls. Use container isolation for any public deployment and enforce usage policies.


---

## Practical Explanations (60-min Classroom Demo)

### **Phase 1: Setup & Authentication (10 min)**

```
1. Start API: python .\vulnshop.py
2. Import Postman collection + environment
3. Run "01 - Auth → Login User1" → save JWT token to environment
4. Run "01 - Auth → Login User2" → save second token
```

**What Students Learn:**
- How tokens are automatically saved to environment variables
- How to switch between user contexts
- Token structure (JWT decode)

---

### **Phase 2: Exploitation (35 min)**

**API1: BOLA Demo**
```
1. Login as User1
2. Run "02 - API1 BOLA → Read other user's order" (read order_id=2 which belongs to user2)
3. RESULT (Vulnerable): You GET order data even though you don't own it ❌
4. RESULT (Secure): You GET 403 Forbidden ✅
```

**Explanation:**
> "The API doesn't check ownership. Any authenticated user can access ANY object by changing the ID in the URL. This is called BOLA (Broken Object Level Authorization). Fix: Always verify object ownership before returning data."

---

**API3: Mass Assignment Demo**
```
1. Login as User1 (normal user, not admin)
2. Run "04 - API3 → Mass Assignment - Escalate to admin"
   - Send PATCH with: {"is_admin": true, "role": "admin"}
3. RESULT (Vulnerable): User1 becomes admin ❌
4. RESULT (Secure): Fields ignored, still normal user ✅
```

**Explanation:**
> "API3 has two flaws: (a) Mass assignment - it blindly updates any field you send, and (b) Excessive data exposure - passwords are returned in responses. Always allowlist fields and strip sensitive data from API responses."

---

**API6: Business Flow Demo**
```
1. Run "07 - API6 → Create Order" (stores order_id in environment)
2. Run "07 - API6 → Confirm order WITHOUT paying"
3. RESULT (Vulnerable): Order status changes to CONFIRMED even though not paid ❌
4. RESULT (Secure): Returns 409 error "Must be PAID first" ✅
```

**Explanation:**
> "The API doesn't enforce business flow rules. You can confirm an order without paying. Always validate state transitions on the server."

---

**API7: SSRF Demo**
```
1. Run "08 - API7 → SSRF - fetch internal URL"
   - Tries to fetch: http://127.0.0.1:5000/api/health
2. RESULT (Vulnerable): API fetches internal endpoint and returns data ❌
3. RESULT (Secure): Returns 403 "Localhost blocked" ✅
```

**Explanation:**
> "SSRF lets attackers use your API server to probe internal networks. Always validate outbound URLs: block internal IPs (127.0.0.1, 10.0.0.0/8, 169.254.169.254 metadata), and only allow whitelisted external APIs."

---

### **Phase 3: Patching & Re-Testing (15 min)**

```
1. Stop vulnshop.py (Ctrl+C)
2. Run: python .\secure_vulnshop.py
3. In Postman: Re-run all tests
4. Show class the PASS results
```

**Explain each fix:**

| Vulnerability | Fix |
|---|---|
| API1 BOLA | Added `require_owner_or_admin()` checks |
| API2 Broken Auth | Hashed passwords with `werkzeug.security`, added rate limiting |
| API3 Mass Assignment | Whitelisted safe fields, removed password from responses |
| API4 Resource Consumption | Added limit caps (max 100, min 1) |
| API5 Function Auth | Added `require_admin()` role checks |
| API6 Business Flow | Enforced `status != PAID` check before confirm |
| API7 SSRF | Added IP validation, block private/loopback ranges |
| API8 Misconfiguration | Disabled DEBUG, restricted CORS, strong default secret |
| API9 Inventory | Removed `/api/v1/debug/users` endpoint entirely |
| API10 Unsafe Consumption | Added allowlist for provider URLs |

---

## Advanced: Setting Instructor Machine IP (for LAN students)

If students are connecting from other machines on the LAN:

```powershell
# Get your machine IP
ipconfig

# Example output: IPv4 Address: 192.168.1.100
```

In Postman Environment, change:
```
base_url: http://192.168.1.100:5000
```

Students can now access:
```
http://192.168.1.100:5000/api/health
```

---

## API Endpoint Reference

### **Authentication**
```
POST /api/auth/login
Body: {"email": "user1@example.com", "password": "Password123"}
```

### **Users**
```
GET /api/users/<id>                      # Get user profile (need token)
PATCH /api/users/<id>                   # Update user (need token)
```

### **Products**
```
GET /api/products?limit=10&offset=0      # List products (no auth needed)
DELETE /api/products/<id>                # Delete product (need token)
```

### **Orders**
```
POST /api/orders                         # Create order (need token)
GET /api/orders/<id>                     # Get order (need token)
POST /api/orders/<id>/pay                # Pay for order (need token)
POST /api/orders/<id>/confirm            # Confirm order (need token)
```

### **Admin**
```
GET /api/admin/users                     # List all users (need admin token)
```

### **SSRF**
```
POST /api/utils/fetch-url
Body: {"url": "http://example.com"}
```

### **Shipping Quote (API10)**
```
POST /api/shipping/quote
Body: {"provider_url": "...", "order_id": 1}
```

---

## Troubleshooting

### **Port 5000 Already in Use**
```powershell
# Find what's using port 5000
netstat -ano | findstr :5000

# Kill the process (replace PID)
taskkill /PID <PID> /F

# Restart API
python .\vulnshop.py
```

### **Module Not Found Errors**
```powershell
# Ensure virtual environment is activated
.\.venv\Scripts\activate

# Reinstall
pip install -r requirements.txt
```

### **JWT Token Issues in Postman**
1. Run `01 - Auth → Login User1` first
2. Check in Postman → Environments → VulnShop - Local Lab → `access_token` is populated
3. If empty, re-run Login

---

## Classroom Teaching Tips

### **5-Minute Recap (Print This)**

**OWASP API Top 10 = the 10 most dangerous API flaws:**

1. **BOLA** - Exposed = no ownership checks
2. **Broken Auth** = weak passwords, no rate limit
3. **Mass Assignment** = blindly updates all fields
4. **Resource Hogging** = no pagination caps
5. **Function Auth** = no role checks
6. **Business Logic** = skips required steps
7. **SSRF** = fetches internal IPs
8. **Misconfig** = debug on, CORS wide open
9. **Inventory** = old endpoints still exposed
10. **Unsafe 3rd Party** = trusts external APIs blindly

**Fix them all:** Always validate, authenticate, and authorize.

---

## Files Overview

| File | Purpose |
|------|---------|
| `vulnshop.py` | Intentionally vulnerable server (for exploitation) |
| `secure_vulnshop.py` | Patched server (for showing fixes) |
| `requirements.txt` | Python dependencies (Flask, JWT, SQLAlchemy, etc.) |
| `VulnShop_Collection.json` | Postman requests + tests (import this) |
| `VulnShop_Environment.json` | Postman variables (import this) |
| `README.md` | This file |

---

## Resources

- **OWASP API Top 10 (2023):** https://owasp.org/www-project-api-security/
- **Flask Documentation:** https://flask.palletsprojects.com/
- **Postman Docs:** https://learning.postman.com/
- **JWT (JSON Web Tokens):** https://jwt.io/

---

**Happy hacking! 🔒**
