# VulnShop Pro - Comprehensive API Documentation

## 🎯 Base URL

**Production:** `https://vulnshop-pro.railway.app` (when deployed)
**Local Development:** `http://localhost:5000`

---

## 📋 Authentication

All endpoints except `/api/health`, `/api/auth/login`, and `/api/auth/register` require JWT authentication.

### **Header Format:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## 🔐 Authentication Endpoints

### **1. Register User**
```http
POST /api/auth/register
Content-Type: application/json

{
  "name": "John Student",
  "email": "john@example.com",
  "password": "SecurePassword123"
}
```

**Response (201 Created):**
```json
{
  "ok": true,
  "message": "User created successfully"
}
```

---

### **2. Login User**
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecurePassword123"
}
```

**Response (200 OK):**
```json
{
  "ok": true,
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "name": "John Student",
    "email": "john@example.com",
    "role": "student",
    "is_admin": false,
    "balance": 1000.0
  }
}
```

---

## 📚 Vulnerability Learning Endpoints

### **1. Get All Vulnerabilities**
```http
GET /api/vulnerabilities?type=API
Authorization: Bearer {token}
```

**Query Parameters:**
- `type` (optional): `API` or `WEB` to filter by type

**Response (200 OK):**
```json
{
  "ok": true,
  "count": 10,
  "vulnerabilities": [
    {
      "id": "owasp-api-01",
      "title": "Broken Object Level Authorization (BOLA)",
      "type": "API",
      "severity": "CRITICAL",
      "cvss_score": 9.1,
      "difficulty": "EASY",
      "time_to_exploit": "5 minutes"
    },
    // ... more vulnerabilities
  ]
}
```

---

### **2. Get Specific Vulnerability**
```http
GET /api/vulnerabilities/owasp-api-01
Authorization: Bearer {token}
```

**Response (200 OK):**
```json
{
  "ok": true,
  "vulnerability": {
    "id": "owasp-api-01",
    "title": "Broken Object Level Authorization (BOLA)",
    "type": "API",
    "owasp_versions": ["2021", "2023"],
    "cwe": "639",
    "severity": "CRITICAL",
    "cvss_score": 9.1,
    "beginner_explanation": "BOLA means an API fails to check if a user owns...",
    "why_it_happens": "Developers assume that only the owner will request...",
    "real_world_impact": {
      "example": "A healthcare API returns any patient's medical records...",
      "data_at_risk": "Personal data, financial info, medical records...",
      "estimated_cost": "Data breach of 1 million users = $4.5M average cost"
    },
    "exploit_steps": [
      "Step 1: Authenticate as User A...",
      "Step 2: Use User A's token to access /api/users/1..."
    ],
    "postman_requests": [ /* collection */ ],
    "vulnerable_code": [ /* code examples */ ],
    "secure_code": [ /* secure versions */ ],
    "remediation": { /* defensive strategies */ }
  },
  "user_progress": {
    "vulnerability_id": "owasp-api-01",
    "status": "not_started",
    "exploits_attempted": 0,
    "remediation_completed": false,
    "score": 0
  }
}
```

---

### **3. Get Beginner Guide**
```http
GET /api/vulnerabilities/owasp-api-01/beginner-guide
Authorization: Bearer {token}
```

**Response (200 OK):**
```json
{
  "ok": true,
  "guide": {
    "title": "Broken Object Level Authorization (BOLA)",
    "explanation": "BOLA means an API fails to check if a user owns the resource...",
    "why_it_happens": "Developers assume that only the owner will request their own resources...",
    "real_world_impact": { /* details */ },
    "difficulty": "EASY"
  }
}
```

**Usage:** Perfect for beginners just starting to learn about a vulnerability.

---

### **4. Get Exploit Guide (Intermediate)**
```http
GET /api/vulnerabilities/owasp-api-01/exploit-guide
Authorization: Bearer {token}
```

**Response (200 OK):**
```json
{
  "ok": true,
  "steps": [
    "Step 1: Authenticate as User A and note your JWT token",
    "Step 2: Use User A's token to access /api/users/1 (your own profile)",
    "Step 3: Observe the response with your user data",
    "Step 4: Change the URL to /api/users/2, /api/users/3, etc.",
    "Step 5: The API returns data for other users (VULNERABLE!)"
  ],
  "postman_requests": [
    {
      "name": "Get own profile",
      "method": "GET",
      "url": "{{base_url}}/api/users/{{user_id}}",
      "headers": { "Authorization": "Bearer {{access_token}}" }
    },
    {
      "name": "Attempt to access other user's profile",
      "method": "GET",
      "url": "{{base_url}}/api/users/999",
      "headers": { "Authorization": "Bearer {{access_token}}" }
    }
  ],
  "burp_payloads": { /* scanner configurations */ },
  "test_cases": [ /* test scenarios */ ]
}
```

**Usage:** Step-by-step hands-on guide with Postman and Burp examples.

---

### **5. Get Remediation Guide (Defensive)**
```http
GET /api/vulnerabilities/owasp-api-01/remediation
Authorization: Bearer {token}
```

**Response (200 OK):**
```json
{
  "ok": true,
  "vulnerable_code": [
    {
      "language": "Python Flask",
      "code": "@app.route('/api/users/<int:user_id>')\n@token_required\ndef get_user(user_id):\n    user = User.query.get(user_id)\n    # VULNERABLE: No check if requesting user owns the resource"
    }
  ],
  "secure_code": [
    {
      "language": "Python Flask",
      "code": "@app.route('/api/users/<int:user_id>')\n@token_required\ndef get_user(current_user, user_id):\n    if current_user.id != user_id:\n        return {'error': 'Forbidden'}, 403  # Authorization check"
    }
  ],
  "best_practices": [
    "Always verify object ownership on the server side",
    "Use access control lists (ACLs) for complex permissions",
    "Never rely on client-side ID values for authorization"
  ],
  "security_controls": [
    "Implement object-level authorization middleware",
    "Use role-based access control (RBAC)"
  ],
  "testing_strategy": [
    "Unit tests for authorization logic",
    "Integration tests with multiple users",
    "Automated API security scanning"
  ]
}
```

**Usage:** Learn how to fix and prevent the vulnerability.

---

## 📊 Progress & Analytics Endpoints

### **1. Get Progress for Specific Vulnerability**
```http
GET /api/progress/owasp-api-01
Authorization: Bearer {token}
```

**Response (200 OK):**
```json
{
  "ok": true,
  "progress": {
    "vulnerability_id": "owasp-api-01",
    "status": "in_progress",
    "exploits_attempted": 3,
    "remediation_completed": false,
    "score": 75
  }
}
```

---

### **2. Update Progress**
```http
POST /api/progress/update/owasp-api-01
Authorization: Bearer {token}
Content-Type: application/json

{
  "status": "completed",
  "exploits_attempted": 5,
  "remediation_completed": true,
  "score": 100
}
```

**Response (200 OK):**
```json
{
  "ok": true,
  "message": "Progress updated"
}
```

---

### **3. Get Dashboard (Learning Summary)**
```http
GET /api/progress/dashboard
Authorization: Bearer {token}
```

**Response (200 OK):**
```json
{
  "ok": true,
  "user": {
    "id": 1,
    "name": "John Student",
    "email": "john@example.com",
    "role": "student"
  },
  "statistics": {
    "total_vulnerabilities": 20,
    "completed": 5,
    "in_progress": 3,
    "not_started": 12,
    "remediation_completed": 2,
    "total_score": 450,
    "completion_percentage": 25.0
  },
  "recent_progress": [
    {
      "vulnerability_id": "owasp-api-01",
      "status": "completed",
      "score": 100
    }
    // ... more recent items
  ]
}
```

---

## 🛡️ Admin Endpoints

### **Get Audit Logs (Admin Only)**
```http
GET /api/logs?limit=100
Authorization: Bearer {admin_token}
```

**Query Parameters:**
- `limit` (optional, default 100): Number of logs to return

**Response (200 OK):**
```json
{
  "ok": true,
  "count": 15,
  "logs": [
    {
      "id": 1,
      "user_id": 5,
      "vulnerability_id": "owasp-api-01",
      "event_type": "EXPLOIT_ATTEMPT",
      "endpoint": "/api/users/999",
      "success": true,
      "ip": "192.168.1.100",
      "timestamp": 1707115200
    }
    // ... more logs
  ]
}
```

---

## 🏥 System Endpoints

### **Health Check**
```http
GET /api/health
```

**Response (200 OK):**
```json
{
  "ok": true,
  "service": "VulnShop Pro API",
  "version": "v2.0",
  "timestamp": 1707115200
}
```

### **Reset Database (Development Only)**
```http
POST /api/setup/reset
```

**Response (200 OK):**
```json
{
  "ok": true,
  "message": "Database reset and seeded"
}
```

---

## 📝 Postman Integration

### **Import VulnShop Collection**

1. **Get collection ID** from `/api/vulnerabilities/{id}/exploit-guide`
2. **Create in Postman:**
   ```
   File → Import → Raw JSON
   Paste the postman_requests array
   ```

3. **Set up environment variables in Postman:**
   ```json
   {
     "base_url": "http://localhost:5000",
     "access_token": "your-token-here",
     "user_id": 1
   }
   ```

---

## 🔍 Burp Suite Integration

### **Scanner Configuration**

1. **Add VulnShop to Burp Scope:**
   - Target → Scope → Include → Add URL
   - Example: `http://localhost:5000`

2. **Use Burp from `/exploit-guide` payloads:**
   - Copy `burp_payloads` from API response
   - Intruder tab → Load payloads
   - Sniper attack on user_ids

3. **Automated Scanning:**
   - Crawl the API first
   - Run active scan
   - Check Scan Issues for vulnerabilities

---

## ⚠️ Error Responses

### **401 Unauthorized**
```json
{
  "ok": false,
  "error": "Invalid credentials"
}
```

### **403 Forbidden**
```json
{
  "ok": false,
  "error": "Unauthorized - Admin access required"
}
```

### **404 Not Found**
```json
{
  "ok": false,
  "error": "Vulnerability not found"
}
```

### **500 Server Error**
```json
{
  "ok": false,
  "error": "Internal server error"
}
```

---

## 💡 Example Workflows

### **Workflow 1: Complete a Vulnerability (Beginner)**

```bash
# 1. Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"student@example.com","password":"pass"}'

# Extract access_token from response

# 2. Get beginner guide
curl http://localhost:5000/api/vulnerabilities/owasp-api-01/beginner-guide \
  -H "Authorization: Bearer {token}"

# 3. Get exploit guide
curl http://localhost:5000/api/vulnerabilities/owasp-api-01/exploit-guide \
  -H "Authorization: Bearer {token}"

# 4. Mark as completed
curl -X POST http://localhost:5000/api/progress/update/owasp-api-01 \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{"status":"completed","exploits_attempted":3,"score":85}'

# 5. View dashboard
curl http://localhost:5000/api/progress/dashboard \
  -H "Authorization: Bearer {token}"
```

---

## 🚀 Rate Limiting (Coming Soon)

- 100 requests per minute per IP
- 10 login attempts per 15 minutes
- DDoS protection via Cloudflare

---

## 📞 Support

- **API Status:** https://status.vulnshop-pro.app
- **Documentation:** https://docs.vulnshop-pro.app
- **GitHub Issues:** https://github.com/vulnshop/pro/issues
- **Community Forum:** https://community.vulnshop-pro.app

---

**Last Updated:** February 5, 2026
**API Version:** 2.0
**Status:** Active & Production-Ready

