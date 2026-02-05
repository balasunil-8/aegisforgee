# Quick Start Guide - AegisForge Postman Collection

## ⚡ 5-Minute Setup

### Step 1: Import Collection (30 seconds)

1. Open **Postman**
2. Click **Import** button (top left)
3. Drag `AegisForge_Complete_Collection.json` or click to browse
4. Click **Import**

### Step 2: Start Servers (1 minute)

**Terminal 1 - RED TEAM (Vulnerable):**
```bash
cd /path/to/aegisforgee
python3 aegisforge_red.py
# Starts on port 5000
```

**Terminal 2 - BLUE TEAM (Secure):**
```bash
cd /path/to/aegisforgee
python3 aegisforge_blue.py
# Starts on port 5001
```

### Step 3: Test Authentication (2 minutes)

Navigate to: `🔴 RED TEAM` → `01 - Authentication`

1. **Register User** - Click Send
   - Creates a test user
   - Status: 200/201

2. **Login User** - Click Send
   - Returns JWT token
   - Token auto-saves to `{{access_token}}`
   - Status: 200

### Step 4: Run Your First Vulnerability Test (1 minute)

Navigate to: `🔴 RED TEAM` → `02 - SQL Injection`

1. **Boolean-Based SQLi - True Condition**
   - Click Send
   - See unfiltered SQL query execution
   - Status: 200 (vulnerability!)

Compare with: `🔵 BLUE TEAM` → `02 - SQL Injection Prevention` → `SQLi Attempt - Boolean`
   - Click Send
   - See proper input validation
   - Status: 400/404 (blocked!)

---

## 🎯 Common Use Cases

### Security Testing
```
1. Run RED TEAM request → Observe vulnerability
2. Run BLUE TEAM request → Observe protection
3. Document findings
```

### Learning
```
1. Start with Authentication requests
2. Progress through each category
3. Read test scripts to understand checks
4. Compare RED vs BLUE implementations
```

### Batch Testing
```
1. Select a folder (e.g., "02 - SQL Injection")
2. Click "Run" (Collection Runner)
3. View automated test results
4. Export report
```

---

## 📊 Quick Reference

| Variable | Value | Auto-Set? |
|----------|-------|-----------|
| `red_base_url` | `http://localhost:5000` | Manual |
| `blue_base_url` | `http://localhost:5001` | Manual |
| `access_token` | *(empty)* | ✅ After login |
| `user_id` | `1` | ✅ After login |
| `csrf_token` | *(empty)* | ✅ After GET /api/csrf-token |
| `admin_token` | *(empty)* | ✅ After admin login |

---

## 🔥 Top 10 Must-Try Requests

### RED TEAM (Vulnerable)
1. **SQLi - Authentication Bypass** - `/api/auth/login` with `' OR '1'='1'--`
2. **XSS - Reflected** - `/api/search?q=<script>alert('XSS')</script>`
3. **IDOR - Access Other Users** - `/api/users/2` (when logged in as user 1)
4. **Command Injection** - `/api/ping?host=127.0.0.1; cat /etc/passwd`
5. **SSRF - Cloud Metadata** - `/api/fetch?url=http://169.254.169.254/latest/meta-data/`

### BLUE TEAM (Secure)
6. **Rate Limiting** - Try 3+ failed logins
7. **Input Sanitization** - XSS attempts get cleaned
8. **IDOR Prevention** - Access denied to other users
9. **CSRF Protection** - Requires token for state changes
10. **Secure Password** - Weak passwords rejected

---

## ⚠️ Troubleshooting

### "Connection Refused"
- ✅ Ensure servers are running on ports 5000/5001
- ✅ Check firewall settings
- ✅ Verify correct base URLs

### "Unauthorized" Errors
- ✅ Run authentication requests first
- ✅ Check `{{access_token}}` is populated
- ✅ Token might be expired - login again

### Tests Failing
- ✅ Normal for RED TEAM (intentionally vulnerable)
- ✅ Some endpoints may not be implemented yet
- ✅ Check server logs for errors

---

## 📚 Next Steps

1. Read `README.md` for comprehensive documentation
2. Explore all 141 requests
3. Customize collection for your needs
4. Create your own test scenarios
5. Share findings with your team

---

## 🆘 Support

- **Documentation**: See `postman/README.md`
- **API Docs**: See `API_DOCUMENTATION.md`
- **Testing Guide**: See `PENTESTLAB_TESTING_GUIDE.md`

---

**Collection Version**: 2.1.0  
**Total Requests**: 141  
**Last Updated**: 2024
