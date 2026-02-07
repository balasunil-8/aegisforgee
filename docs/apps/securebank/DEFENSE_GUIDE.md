# SecureBank Defense Guide

Comprehensive guide to security mechanisms and defenses implemented in SecureBank Blue Team.

---

## Table of Contents

1. [Introduction](#introduction)
2. [SQL Injection Defenses](#sql-injection-defenses)
3. [IDOR Defenses](#idor-defenses)
4. [Race Condition Defenses](#race-condition-defenses)
5. [XSS Defenses](#xss-defenses)
6. [Mass Assignment Defenses](#mass-assignment-defenses)
7. [CSRF Defenses](#csrf-defenses)
8. [Additional Security Layers](#additional-security-layers)
9. [Testing Defenses](#testing-defenses)
10. [Best Practices](#best-practices)

---

## Introduction

### Purpose

This guide explains the security mechanisms implemented in SecureBank Blue Team. For each vulnerability in Red Team, Blue Team implements industry-standard defenses to prevent exploitation.

### Defense-in-Depth

SecureBank Blue Team uses a layered security approach:

1. **Input Validation**: Validate all user input
2. **Output Encoding**: Sanitize all output
3. **Authentication**: Verify user identity
4. **Authorization**: Check access permissions
5. **Session Management**: Secure session handling
6. **Cryptography**: Encrypt sensitive data
7. **Logging**: Track security events

### Learning Objectives

After studying these defenses, you will be able to:
- Implement secure coding practices
- Compare vulnerable vs secure code
- Test security mechanisms
- Recommend appropriate defenses
- Avoid common security mistakes

---

## SQL Injection Defenses

### The Problem

Red Team concatenates user input directly into SQL queries:

```python
# VULNERABLE CODE (Red Team)
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Direct string concatenation - DANGEROUS!
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
```

**Attack:**
```python
username = "admin' OR '1'='1' --"
# Resulting query: SELECT * FROM users WHERE username='admin' OR '1'='1' --' AND password='...'
# The OR '1'='1' bypasses authentication!
```

### Defense 1: Parameterized Queries (Primary Defense)

```python
# SECURE CODE (Blue Team)
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Parameterized query - SAFE!
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
```

**How It Works:**
- Parameters are sent separately from SQL query
- Database driver handles escaping automatically
- Special characters treated as data, not code
- Prevents injection regardless of input

**Key Points:**
- Use `?` placeholders (SQLite) or `%s` (MySQL/PostgreSQL)
- Never concatenate user input into queries
- Works for all query types (SELECT, INSERT, UPDATE, DELETE)

### Defense 2: Input Validation

```python
# SECURE CODE (Blue Team)
import re

def validate_username(username):
    """Validate username format"""
    # Only allow alphanumeric and underscore
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        raise ValueError("Invalid username format")
    return username

def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Validate input BEFORE using it
    try:
        username = validate_username(username)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
```

**Validation Rules:**
- Whitelist allowed characters
- Check length limits
- Validate format (email, phone, etc.)
- Reject suspicious patterns

### Defense 3: ORM (Object-Relational Mapping)

```python
# SECURE CODE (Blue Team with SQLAlchemy)
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True)
    username = Column(String(50))
    password = Column(String(255))

def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # ORM query - automatically parameterized
    user = db_session.query(User).filter(
        User.username == username,
        User.password == password
    ).first()
    
    if user:
        return jsonify({"success": True})
    return jsonify({"success": False})
```

**Benefits:**
- Automatic parameterization
- Type safety
- Cleaner code
- Database-agnostic

### Defense 4: Least Privilege

```python
# Database configuration
import sqlite3

def create_connection():
    """Create database connection with limited privileges"""
    conn = sqlite3.connect('securebank.db')
    
    # Grant minimal permissions
    # In production: Use separate DB user with only SELECT, INSERT, UPDATE
    # No DROP, DELETE on critical tables
    # No GRANT privileges
    
    return conn

# In production SQL (PostgreSQL example):
"""
CREATE USER app_user WITH PASSWORD 'secure_password';
GRANT SELECT, INSERT, UPDATE ON users TO app_user;
GRANT SELECT, INSERT, UPDATE ON accounts TO app_user;
-- No DELETE or DROP privileges
"""
```

### Defense 5: Web Application Firewall (WAF)

```python
# SECURE CODE (Blue Team)
from werkzeug.security import safe_str_cmp

def detect_sql_injection(input_string):
    """Detect common SQL injection patterns"""
    
    sql_keywords = [
        'union', 'select', 'insert', 'update', 'delete', 'drop',
        'create', 'alter', '--', '/*', '*/', 'xp_', 'sp_', 'exec',
        'execute', 'script', 'javascript', 'eval', 'expression'
    ]
    
    input_lower = input_string.lower()
    
    for keyword in sql_keywords:
        if keyword in input_lower:
            return True
    
    # Check for suspicious patterns
    patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL meta-characters
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # SQL operators
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",  # SQL 'or'
    ]
    
    for pattern in patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True
    
    return False

def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Check for SQL injection attempts
    if detect_sql_injection(username) or detect_sql_injection(password):
        # Log the attempt
        log_security_event('SQL Injection Attempt', {
            'username': username,
            'ip': request.remote_addr
        })
        return jsonify({"error": "Invalid input"}), 400
    
    # Proceed with parameterized query
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
```

### Testing SQL Injection Defenses

```python
# test_sql_injection_defense.py
import requests

def test_sql_injection_defense():
    """Test that SQL injection is prevented"""
    
    API_URL = "http://localhost:5002/api/login"  # Blue Team
    
    payloads = [
        "' OR '1'='1",
        "admin' --",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users; --"
    ]
    
    for payload in payloads:
        response = requests.post(API_URL, json={
            'username': payload,
            'password': 'anything'
        })
        
        # Should fail or return error
        assert response.status_code != 200 or not response.json().get('success'), \
            f"SQL injection defense failed for payload: {payload}"
    
    print("[+] All SQL injection attempts blocked successfully")

if __name__ == "__main__":
    test_sql_injection_defense()
```

---

## IDOR Defenses

### The Problem

Red Team exposes direct object references without authorization:

```python
# VULNERABLE CODE (Red Team)
@app.route('/api/account/<int:account_id>', methods=['GET'])
def get_account(account_id):
    # NO authorization check!
    query = "SELECT * FROM accounts WHERE account_id=?"
    cursor.execute(query, (account_id,))
    account = cursor.fetchone()
    
    if account:
        return jsonify({
            "account_id": account[0],
            "balance": account[2]
        })
```

**Attack:**
```bash
# Alice can access Bob's account
curl http://localhost:5001/api/account/1002 -b alice_cookies.txt
```

### Defense 1: Authorization Checks (Primary Defense)

```python
# SECURE CODE (Blue Team)
@app.route('/api/account/<int:account_id>', methods=['GET'])
def get_account(account_id):
    # Get current user from session
    current_user_id = session.get('user_id')
    
    if not current_user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # AUTHORIZATION CHECK: User owns this account?
    query = """
        SELECT * FROM accounts 
        WHERE account_id=? AND user_id=?
    """
    cursor.execute(query, (account_id, current_user_id))
    account = cursor.fetchone()
    
    if account:
        return jsonify({
            "account_id": account[0],
            "balance": account[2]
        })
    
    # Return 403 Forbidden (not 404) to prevent enumeration
    return jsonify({"error": "Access denied"}), 403
```

**Key Points:**
- Always check user owns the resource
- Use session data, not request parameters
- Return 403 for unauthorized access
- Log suspicious access attempts

### Defense 2: Indirect Reference Maps

```python
# SECURE CODE (Blue Team)
import secrets

# Create mapping of indirect references to actual IDs
reference_maps = {}

def create_indirect_reference(user_id, account_id):
    """Create indirect reference for account"""
    # Generate random token
    token = secrets.token_urlsafe(16)
    
    # Store mapping
    reference_maps[token] = {
        'user_id': user_id,
        'account_id': account_id
    }
    
    return token

@app.route('/api/account/<string:reference>', methods=['GET'])
def get_account(reference):
    current_user_id = session.get('user_id')
    
    # Look up actual ID from reference
    mapping = reference_maps.get(reference)
    
    if not mapping:
        return jsonify({"error": "Invalid reference"}), 404
    
    # Verify user owns this account
    if mapping['user_id'] != current_user_id:
        return jsonify({"error": "Access denied"}), 403
    
    # Now safe to query actual account
    account_id = mapping['account_id']
    query = "SELECT * FROM accounts WHERE account_id=?"
    cursor.execute(query, (account_id,))
    account = cursor.fetchone()
    
    return jsonify({"balance": account[2]})
```

### Defense 3: UUIDs Instead of Sequential IDs

```python
# SECURE CODE (Blue Team)
import uuid
from sqlalchemy import Column, String

class Account(Base):
    __tablename__ = 'accounts'
    
    # Use UUID instead of sequential integer
    account_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36))
    balance = Column(Float)

# Example account_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
# Much harder to guess than sequential 1001, 1002, 1003...
```

### Defense 4: Access Control Lists (ACLs)

```python
# SECURE CODE (Blue Team)
class AccessControl:
    """Centralized access control"""
    
    @staticmethod
    def can_access_account(user_id, account_id):
        """Check if user can access account"""
        
        # Check ownership
        query = "SELECT 1 FROM accounts WHERE account_id=? AND user_id=?"
        result = cursor.execute(query, (account_id, user_id)).fetchone()
        
        if result:
            return True
        
        # Check if user has shared access
        query = """
            SELECT 1 FROM account_permissions 
            WHERE account_id=? AND user_id=? AND permission='read'
        """
        result = cursor.execute(query, (account_id, user_id)).fetchone()
        
        return result is not None
    
    @staticmethod
    def can_modify_account(user_id, account_id):
        """Check if user can modify account"""
        
        query = "SELECT 1 FROM accounts WHERE account_id=? AND user_id=?"
        result = cursor.execute(query, (account_id, user_id)).fetchone()
        
        return result is not None

@app.route('/api/account/<int:account_id>', methods=['GET'])
def get_account(account_id):
    user_id = session.get('user_id')
    
    # Use centralized access control
    if not AccessControl.can_access_account(user_id, account_id):
        return jsonify({"error": "Access denied"}), 403
    
    # Proceed with query...
```

### Testing IDOR Defenses

```python
# test_idor_defense.py
import requests

def test_idor_defense():
    """Test that IDOR is prevented"""
    
    # Login as Alice
    session_alice = requests.Session()
    session_alice.post('http://localhost:5002/api/login', json={
        'username': 'alice',
        'password': 'alice123'
    })
    
    # Try to access Bob's account (should fail)
    response = session_alice.get('http://localhost:5002/api/account/1002')
    
    assert response.status_code == 403, "IDOR defense failed!"
    assert response.json().get('error') == 'Access denied'
    
    # Try to access own account (should succeed)
    response = session_alice.get('http://localhost:5002/api/account/1001')
    
    assert response.status_code == 200, "Own account access failed!"
    
    print("[+] IDOR defenses working correctly")

if __name__ == "__main__":
    test_idor_defense()
```

---

## Race Condition Defenses

### The Problem

Red Team has non-atomic operations on shared resources:

```python
# VULNERABLE CODE (Red Team)
@app.route('/api/transfer', methods=['POST'])
def transfer():
    from_account = request.json.get('from_account')
    amount = request.json.get('amount')
    
    # Step 1: Check balance
    cursor.execute("SELECT balance FROM accounts WHERE account_id=?", (from_account,))
    balance = cursor.fetchone()[0]
    
    # Step 2: Validate (RACE WINDOW HERE!)
    if balance < amount:
        return jsonify({"error": "Insufficient funds"})
    
    # Step 3: Update balance
    new_balance = balance - amount
    cursor.execute("UPDATE accounts SET balance=? WHERE account_id=?", 
                   (new_balance, from_account))
    conn.commit()
```

**Attack:**
Multiple simultaneous requests can bypass the balance check.

### Defense 1: Database Transactions (Primary Defense)

```python
# SECURE CODE (Blue Team)
@app.route('/api/transfer', methods=['POST'])
def transfer():
    from_account = request.json.get('from_account')
    to_account = request.json.get('to_account')
    amount = request.json.get('amount')
    
    try:
        # Begin transaction
        conn.execute("BEGIN IMMEDIATE")
        
        # Lock the row for update
        cursor.execute(
            "SELECT balance FROM accounts WHERE account_id=? FOR UPDATE",
            (from_account,)
        )
        balance = cursor.fetchone()[0]
        
        # Validate
        if balance < amount:
            conn.rollback()
            return jsonify({"error": "Insufficient funds"}), 400
        
        # Atomic updates
        cursor.execute(
            "UPDATE accounts SET balance=balance-? WHERE account_id=?",
            (amount, from_account)
        )
        cursor.execute(
            "UPDATE accounts SET balance=balance+? WHERE account_id=?",
            (amount, to_account)
        )
        
        # Commit transaction
        conn.commit()
        return jsonify({"success": True})
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
```

**Key Points:**
- Use `BEGIN IMMEDIATE` for SQLite
- Use `FOR UPDATE` to lock rows
- Atomic operations: `balance=balance-?`
- Always rollback on error

### Defense 2: Application-Level Locking

```python
# SECURE CODE (Blue Team)
import threading

# Create locks for each account
account_locks = {}
locks_mutex = threading.Lock()

def get_account_lock(account_id):
    """Get or create lock for account"""
    with locks_mutex:
        if account_id not in account_locks:
            account_locks[account_id] = threading.Lock()
        return account_locks[account_id]

@app.route('/api/transfer', methods=['POST'])
def transfer():
    from_account = request.json.get('from_account')
    to_account = request.json.get('to_account')
    amount = request.json.get('amount')
    
    # Get locks for both accounts (in order to prevent deadlock)
    accounts = sorted([from_account, to_account])
    lock1 = get_account_lock(accounts[0])
    lock2 = get_account_lock(accounts[1])
    
    # Acquire locks
    with lock1:
        with lock2:
            # Now safe to perform transfer
            cursor.execute("SELECT balance FROM accounts WHERE account_id=?", 
                         (from_account,))
            balance = cursor.fetchone()[0]
            
            if balance < amount:
                return jsonify({"error": "Insufficient funds"}), 400
            
            # Perform transfer
            cursor.execute("UPDATE accounts SET balance=balance-? WHERE account_id=?",
                         (amount, from_account))
            cursor.execute("UPDATE accounts SET balance=balance+? WHERE account_id=?",
                         (amount, to_account))
            conn.commit()
            
            return jsonify({"success": True})
```

### Defense 3: Optimistic Locking

```python
# SECURE CODE (Blue Team)
class Account(Base):
    __tablename__ = 'accounts'
    account_id = Column(Integer, primary_key=True)
    balance = Column(Float)
    version = Column(Integer, default=0)  # Version number

@app.route('/api/transfer', methods=['POST'])
def transfer():
    from_account = request.json.get('from_account')
    to_account = request.json.get('to_account')
    amount = request.json.get('amount')
    
    # Get current version
    cursor.execute("SELECT balance, version FROM accounts WHERE account_id=?",
                   (from_account,))
    balance, version = cursor.fetchone()
    
    if balance < amount:
        return jsonify({"error": "Insufficient funds"}), 400
    
    # Update with version check
    cursor.execute("""
        UPDATE accounts 
        SET balance=balance-?, version=version+1 
        WHERE account_id=? AND version=?
    """, (amount, from_account, version))
    
    # Check if update succeeded
    if cursor.rowcount == 0:
        # Version mismatch - someone else modified it
        return jsonify({"error": "Concurrent modification detected. Please retry."}), 409
    
    # Update recipient
    cursor.execute("UPDATE accounts SET balance=balance+? WHERE account_id=?",
                   (amount, to_account))
    
    conn.commit()
    return jsonify({"success": True})
```

### Defense 4: Idempotency Keys

```python
# SECURE CODE (Blue Team)
import uuid

processed_transactions = set()

@app.route('/api/transfer', methods=['POST'])
def transfer():
    # Client generates unique key for each request
    idempotency_key = request.headers.get('Idempotency-Key')
    
    if not idempotency_key:
        return jsonify({"error": "Idempotency-Key required"}), 400
    
    # Check if already processed
    if idempotency_key in processed_transactions:
        return jsonify({"error": "Transaction already processed"}), 409
    
    # Process transfer...
    # ... transfer logic ...
    
    # Mark as processed
    processed_transactions.add(idempotency_key)
    
    return jsonify({"success": True})
```

### Testing Race Condition Defenses

```python
# test_race_condition_defense.py
import requests
import threading
import time

def test_race_condition_defense():
    """Test that race conditions are prevented"""
    
    # Login
    session = requests.Session()
    session.post('http://localhost:5002/api/login', json={
        'username': 'alice',
        'password': 'alice123'
    })
    
    # Get initial balance
    response = session.get('http://localhost:5002/api/account/1001')
    initial_balance = response.json()['balance']
    
    print(f"Initial balance: ${initial_balance}")
    
    # Transfer amount
    amount = 100
    threads_count = 10
    
    # Create transfer function
    results = []
    def transfer():
        response = session.post('http://localhost:5002/api/transfer', json={
            'from_account': 1001,
            'to_account': 1002,
            'amount': amount
        })
        results.append(response.json())
    
    # Launch simultaneous requests
    threads = []
    for i in range(threads_count):
        t = threading.Thread(target=transfer)
        threads.append(t)
        t.start()
    
    # Wait for completion
    for t in threads:
        t.join()
    
    # Check final balance
    time.sleep(1)
    response = session.get('http://localhost:5002/api/account/1001')
    final_balance = response.json()['balance']
    
    print(f"Final balance: ${final_balance}")
    
    # Calculate expected balance
    successful = len([r for r in results if r.get('success')])
    expected_balance = initial_balance - (amount * successful)
    
    print(f"Successful transfers: {successful}")
    print(f"Expected balance: ${expected_balance}")
    
    # Verify balance is correct
    assert final_balance == expected_balance, \
        f"Race condition defense failed! Expected ${expected_balance}, got ${final_balance}"
    
    print("[+] Race condition defenses working correctly")

if __name__ == "__main__":
    test_race_condition_defense()
```

---

## XSS Defenses

### The Problem

Red Team outputs user input without sanitization:

```python
# VULNERABLE CODE (Red Team)
@app.route('/api/profile/<int:user_id>', methods=['GET'])
def get_profile(user_id):
    cursor.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
    user = cursor.fetchone()
    
    # Returns unsanitized data
    return jsonify({
        "full_name": user[3]  # Could contain <script>alert('XSS')</script>
    })
```

```javascript
// Frontend (vulnerable)
function displayProfile(profile) {
    // Direct HTML insertion
    document.getElementById('profile').innerHTML = 
        `<h2>${profile.full_name}</h2>`;
}
```

### Defense 1: Output Encoding (Primary Defense)

```python
# SECURE CODE (Blue Team)
import html

@app.route('/api/profile/<int:user_id>', methods=['GET'])
def get_profile(user_id):
    cursor.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
    user = cursor.fetchone()
    
    # Escape HTML entities
    return jsonify({
        "full_name": html.escape(user[3]),
        "email": html.escape(user[2])
    })
```

```javascript
// Frontend (secure)
function displayProfile(profile) {
    // Use textContent instead of innerHTML
    const h2 = document.createElement('h2');
    h2.textContent = profile.full_name;  // Auto-escapes
    
    document.getElementById('profile').appendChild(h2);
}
```

**Key Points:**
- Use `html.escape()` in Python
- Use `textContent` or `innerText` in JavaScript
- Never use `innerHTML` with user data
- Escape for context (HTML, JavaScript, URL, CSS)

### Defense 2: Content Security Policy (CSP)

```python
# SECURE CODE (Blue Team)
@app.after_request
def set_csp(response):
    """Set Content Security Policy headers"""
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    return response
```

**CSP Directives:**
- `default-src 'self'`: Only load resources from same origin
- `script-src 'self'`: Only execute scripts from same origin
- `style-src 'self' 'unsafe-inline'`: Styles from same origin + inline
- `img-src 'self' data:`: Images from same origin + data URIs

### Defense 3: Input Validation

```python
# SECURE CODE (Blue Team)
import re
from bleach import clean

def sanitize_input(input_string, max_length=100):
    """Sanitize user input"""
    
    # Trim whitespace
    input_string = input_string.strip()
    
    # Check length
    if len(input_string) > max_length:
        raise ValueError("Input too long")
    
    # Remove dangerous characters
    # Allow only alphanumeric, spaces, and basic punctuation
    if not re.match(r'^[a-zA-Z0-9\s\.\,\!\?\-]+$', input_string):
        raise ValueError("Invalid characters in input")
    
    return input_string

def sanitize_html(html_string):
    """Sanitize HTML input"""
    
    # Allow only safe tags
    allowed_tags = ['p', 'b', 'i', 'u', 'em', 'strong']
    allowed_attrs = {}
    
    # Strip dangerous tags and attributes
    clean_html = clean(
        html_string,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip=True
    )
    
    return clean_html

@app.route('/api/profile', methods=['PUT'])
def update_profile():
    data = request.json
    
    try:
        # Sanitize all inputs
        full_name = sanitize_input(data.get('full_name'), max_length=50)
        email = sanitize_input(data.get('email'), max_length=100)
        
        # Update profile...
        
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
```

### Defense 4: HTTPOnly and Secure Cookies

```python
# SECURE CODE (Blue Team)
@app.route('/api/login', methods=['POST'])
def login():
    # ... authentication logic ...
    
    response = jsonify({"success": True})
    
    # Set secure cookie
    response.set_cookie(
        'session_id',
        value=session_token,
        httponly=True,      # Prevent JavaScript access
        secure=True,         # Only send over HTTPS
        samesite='Strict',   # Prevent CSRF
        max_age=3600         # 1 hour expiration
    )
    
    return response
```

### Defense 5: Framework Protections

```javascript
// React (auto-escaping)
function ProfileComponent({ profile }) {
    // React automatically escapes
    return (
        <div>
            <h2>{profile.full_name}</h2>
            <p>{profile.email}</p>
        </div>
    );
}

// Angular (auto-escaping)
// In template:
// <h2>{{ profile.full_name }}</h2>
// Angular automatically escapes
```

### Testing XSS Defenses

```python
# test_xss_defense.py
import requests

def test_xss_defense():
    """Test that XSS is prevented"""
    
    session = requests.Session()
    session.post('http://localhost:5002/api/login', json={
        'username': 'alice',
        'password': 'alice123'
    })
    
    xss_payloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
    ]
    
    for payload in xss_payloads:
        # Try to inject XSS
        response = session.put('http://localhost:5002/api/profile', json={
            'full_name': payload
        })
        
        # Get profile back
        profile_response = session.get('http://localhost:5002/api/profile')
        profile = profile_response.json()
        
        # Check if payload is escaped
        assert payload not in profile.get('full_name', ''), \
            f"XSS defense failed for payload: {payload}"
        
        # Should be escaped (e.g., &lt;script&gt;)
        assert '&lt;' in profile.get('full_name', '') or \
               '<' not in profile.get('full_name', ''), \
            "XSS not properly escaped"
    
    print("[+] All XSS payloads properly escaped")

if __name__ == "__main__":
    test_xss_defense()
```

---

## Mass Assignment Defenses

### The Problem

Red Team accepts all request parameters:

```python
# VULNERABLE CODE (Red Team)
@app.route('/api/profile', methods=['PUT'])
def update_profile():
    data = request.json
    
    # Updates ALL fields from request
    fields = []
    values = []
    for key, value in data.items():
        fields.append(f"{key}=?")
        values.append(value)
    
    query = f"UPDATE users SET {', '.join(fields)} WHERE user_id=?"
    # User can modify balance, is_admin, etc.!
```

### Defense 1: Field Whitelisting (Primary Defense)

```python
# SECURE CODE (Blue Team)
@app.route('/api/profile', methods=['PUT'])
def update_profile():
    user_id = session.get('user_id')
    data = request.json
    
    # WHITELIST: Only allow specific fields
    ALLOWED_FIELDS = ['email', 'phone', 'full_name', 'address']
    
    fields = []
    values = []
    
    for key, value in data.items():
        if key in ALLOWED_FIELDS:  # Only whitelisted fields
            fields.append(f"{key}=?")
            values.append(value)
        else:
            # Log suspicious attempt
            log_security_event('Mass Assignment Attempt', {
                'user_id': user_id,
                'attempted_field': key
            })
    
    if not fields:
        return jsonify({"error": "No valid fields to update"}), 400
    
    query = f"UPDATE users SET {', '.join(fields)} WHERE user_id=?"
    values.append(user_id)
    
    cursor.execute(query, values)
    conn.commit()
    
    return jsonify({"success": True})
```

### Defense 2: Data Transfer Objects (DTOs)

```python
# SECURE CODE (Blue Team)
from dataclasses import dataclass
from typing import Optional

@dataclass
class ProfileUpdateDTO:
    """Data Transfer Object for profile updates"""
    email: Optional[str] = None
    phone: Optional[str] = None
    full_name: Optional[str] = None
    address: Optional[str] = None
    
    # NO balance, is_admin, or other sensitive fields

@app.route('/api/profile', methods=['PUT'])
def update_profile():
    user_id = session.get('user_id')
    data = request.json
    
    # Create DTO (only allowed fields)
    try:
        profile_dto = ProfileUpdateDTO(**{
            k: v for k, v in data.items() 
            if k in ProfileUpdateDTO.__annotations__
        })
    except TypeError:
        return jsonify({"error": "Invalid fields"}), 400
    
    # Update only DTO fields
    updates = {}
    if profile_dto.email:
        updates['email'] = profile_dto.email
    if profile_dto.phone:
        updates['phone'] = profile_dto.phone
    if profile_dto.full_name:
        updates['full_name'] = profile_dto.full_name
    if profile_dto.address:
        updates['address'] = profile_dto.address
    
    # Build query from validated data
    fields = [f"{k}=?" for k in updates.keys()]
    values = list(updates.values()) + [user_id]
    
    query = f"UPDATE users SET {', '.join(fields)} WHERE user_id=?"
    cursor.execute(query, values)
    conn.commit()
    
    return jsonify({"success": True})
```

### Defense 3: Explicit Binding

```python
# SECURE CODE (Blue Team)
@app.route('/api/profile', methods=['PUT'])
def update_profile():
    user_id = session.get('user_id')
    data = request.json
    
    # Explicitly bind each field
    email = data.get('email')
    phone = data.get('phone')
    full_name = data.get('full_name')
    address = data.get('address')
    
    # Validate each field
    if email and not is_valid_email(email):
        return jsonify({"error": "Invalid email"}), 400
    
    if phone and not is_valid_phone(phone):
        return jsonify({"error": "Invalid phone"}), 400
    
    # Update only explicit fields
    query = """
        UPDATE users 
        SET email=?, phone=?, full_name=?, address=?
        WHERE user_id=?
    """
    cursor.execute(query, (email, phone, full_name, address, user_id))
    conn.commit()
    
    return jsonify({"success": True})
```

### Defense 4: ORM with Protected Attributes

```python
# SECURE CODE (Blue Team with SQLAlchemy)
from sqlalchemy.ext.hybrid import hybrid_property

class User(Base):
    __tablename__ = 'users'
    
    user_id = Column(Integer, primary_key=True)
    username = Column(String(50))
    email = Column(String(100))
    _balance = Column('balance', Float)  # Protected
    _is_admin = Column('is_admin', Boolean)  # Protected
    
    # Read-only properties
    @hybrid_property
    def balance(self):
        return self._balance
    
    @hybrid_property
    def is_admin(self):
        return self._is_admin
    
    # Only allow updating specific fields
    def update_profile(self, email=None, phone=None):
        if email:
            self.email = email
        if phone:
            self.phone = phone
        # balance and is_admin cannot be updated

@app.route('/api/profile', methods=['PUT'])
def update_profile():
    user_id = session.get('user_id')
    data = request.json
    
    user = db_session.query(User).get(user_id)
    
    # Only allowed fields can be updated
    user.update_profile(
        email=data.get('email'),
        phone=data.get('phone')
    )
    
    db_session.commit()
    return jsonify({"success": True})
```

### Testing Mass Assignment Defenses

```python
# test_mass_assignment_defense.py
import requests

def test_mass_assignment_defense():
    """Test that mass assignment is prevented"""
    
    session = requests.Session()
    session.post('http://localhost:5002/api/login', json={
        'username': 'alice',
        'password': 'alice123'
    })
    
    # Get initial balance
    response = session.get('http://localhost:5002/api/account/1001')
    initial_balance = response.json()['balance']
    
    print(f"Initial balance: ${initial_balance}")
    
    # Try to modify balance via mass assignment
    response = session.put('http://localhost:5002/api/profile', json={
        'email': 'alice@newmail.com',
        'balance': 999999,  # Attempt to modify balance
        'is_admin': True    # Attempt to become admin
    })
    
    # Should succeed (for allowed fields) but ignore dangerous fields
    assert response.status_code == 200, "Profile update should succeed"
    
    # Check balance didn't change
    response = session.get('http://localhost:5002/api/account/1001')
    final_balance = response.json()['balance']
    
    assert final_balance == initial_balance, \
        f"Mass assignment defense failed! Balance changed from ${initial_balance} to ${final_balance}"
    
    print("[+] Mass assignment defenses working correctly")
    print(f"[+] Balance remained ${final_balance}")

if __name__ == "__main__":
    test_mass_assignment_defense()
```

---

## CSRF Defenses

### The Problem

Red Team doesn't validate request origin:

```python
# VULNERABLE CODE (Red Team)
@app.route('/api/transfer', methods=['POST'])
def transfer():
    # Only checks session cookie (sent automatically)
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Process transfer
    # Attacker can trigger this from evil.com!
```

### Defense 1: CSRF Tokens (Primary Defense)

```python
# SECURE CODE (Blue Team)
import secrets

@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    """Generate and return CSRF token"""
    token = secrets.token_urlsafe(32)
    session['csrf_token'] = token
    return jsonify({"csrf_token": token})

def verify_csrf_token():
    """Verify CSRF token"""
    # Get token from header or form
    token = request.headers.get('X-CSRF-Token') or \
            request.form.get('csrf_token')
    
    # Get token from session
    session_token = session.get('csrf_token')
    
    if not token or not session_token:
        return False
    
    # Compare tokens (timing-safe comparison)
    return secrets.compare_digest(token, session_token)

@app.route('/api/transfer', methods=['POST'])
def transfer():
    # Verify CSRF token
    if not verify_csrf_token():
        log_security_event('CSRF Attempt', {
            'user_id': session.get('user_id'),
            'ip': request.remote_addr
        })
        return jsonify({"error": "Invalid CSRF token"}), 403
    
    # Proceed with transfer
    # ...
```

```javascript
// Frontend - Include CSRF token
async function makeTransfer(data) {
    // Get CSRF token
    const tokenResponse = await fetch('/api/csrf-token');
    const {csrf_token} = await tokenResponse.json();
    
    // Include in request
    return fetch('/api/transfer', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrf_token
        },
        body: JSON.stringify(data)
    });
}
```

### Defense 2: SameSite Cookies

```python
# SECURE CODE (Blue Team)
@app.route('/api/login', methods=['POST'])
def login():
    # ... authentication ...
    
    response = jsonify({"success": True})
    
    # Set SameSite cookie
    response.set_cookie(
        'session_id',
        value=session_token,
        samesite='Strict',  # or 'Lax'
        httponly=True,
        secure=True
    )
    
    return response
```

**SameSite Options:**
- `Strict`: Cookie never sent on cross-site requests
- `Lax`: Cookie sent on top-level navigation (links, not AJAX)
- `None`: Cookie sent on all requests (requires Secure flag)

### Defense 3: Double Submit Cookie

```python
# SECURE CODE (Blue Team)
@app.route('/api/transfer', methods=['POST'])
def transfer():
    # Get token from cookie
    cookie_token = request.cookies.get('csrf_token')
    
    # Get token from request
    request_token = request.headers.get('X-CSRF-Token')
    
    # Compare tokens
    if not cookie_token or not request_token:
        return jsonify({"error": "CSRF token required"}), 403
    
    if not secrets.compare_digest(cookie_token, request_token):
        return jsonify({"error": "Invalid CSRF token"}), 403
    
    # Proceed with transfer
    # ...
```

### Defense 4: Origin/Referer Validation

```python
# SECURE CODE (Blue Team)
def verify_origin():
    """Verify request origin"""
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')
    
    allowed_origins = [
        'http://localhost:8000',
        'https://securebank.example.com'
    ]
    
    # Check Origin header
    if origin and origin in allowed_origins:
        return True
    
    # Check Referer header
    if referer:
        for allowed_origin in allowed_origins:
            if referer.startswith(allowed_origin):
                return True
    
    return False

@app.route('/api/transfer', methods=['POST'])
def transfer():
    # Verify origin
    if not verify_origin():
        log_security_event('CSRF Attempt - Invalid Origin', {
            'origin': request.headers.get('Origin'),
            'referer': request.headers.get('Referer'),
            'ip': request.remote_addr
        })
        return jsonify({"error": "Invalid request origin"}), 403
    
    # Proceed with transfer
    # ...
```

### Testing CSRF Defenses

```python
# test_csrf_defense.py
import requests

def test_csrf_defense():
    """Test that CSRF is prevented"""
    
    # Login
    session = requests.Session()
    session.post('http://localhost:5002/api/login', json={
        'username': 'alice',
        'password': 'alice123'
    })
    
    # Try transfer without CSRF token (should fail)
    response = session.post('http://localhost:5002/api/transfer', json={
        'from_account': 1001,
        'to_account': 1002,
        'amount': 100
    })
    
    assert response.status_code == 403, "CSRF defense failed - transfer succeeded without token!"
    
    # Get CSRF token
    token_response = session.get('http://localhost:5002/api/csrf-token')
    csrf_token = token_response.json()['csrf_token']
    
    # Try with CSRF token (should succeed)
    response = session.post(
        'http://localhost:5002/api/transfer',
        json={
            'from_account': 1001,
            'to_account': 1002,
            'amount': 100
        },
        headers={'X-CSRF-Token': csrf_token}
    )
    
    assert response.status_code == 200, "Transfer with CSRF token should succeed"
    
    print("[+] CSRF defenses working correctly")

if __name__ == "__main__":
    test_csrf_defense()
```

---

## Additional Security Layers

### 1. Rate Limiting

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Prevent brute force attacks
    pass
```

### 2. Security Headers

```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

### 3. Input Validation Library

```python
from marshmallow import Schema, fields, validate

class TransferSchema(Schema):
    from_account = fields.Int(required=True, validate=validate.Range(min=1000, max=9999))
    to_account = fields.Int(required=True, validate=validate.Range(min=1000, max=9999))
    amount = fields.Float(required=True, validate=validate.Range(min=0.01, max=10000))

@app.route('/api/transfer', methods=['POST'])
def transfer():
    schema = TransferSchema()
    errors = schema.validate(request.json)
    
    if errors:
        return jsonify({"errors": errors}), 400
    
    # Proceed with validated data
```

### 4. Logging and Monitoring

```python
import logging

# Configure security logger
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.WARNING)

def log_security_event(event_type, details):
    """Log security events"""
    security_logger.warning(
        f"Security Event: {event_type}",
        extra={
            'event_type': event_type,
            'details': details,
            'timestamp': datetime.now().isoformat(),
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        }
    )
```

---

## Testing Defenses

### Comprehensive Security Test Suite

```python
# test_all_defenses.py
import requests
import threading
import time

class SecurityTestSuite:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        
    def login(self):
        """Login to application"""
        response = self.session.post(f'{self.base_url}/api/login', json={
            'username': 'alice',
            'password': 'alice123'
        })
        return response.json().get('success', False)
    
    def test_sql_injection(self):
        """Test SQL injection defenses"""
        print("\n[+] Testing SQL injection defenses...")
        
        payloads = ["' OR '1'='1", "admin' --", "' UNION SELECT NULL--"]
        
        for payload in payloads:
            response = self.session.post(f'{self.base_url}/api/login', json={
                'username': payload,
                'password': 'anything'
            })
            
            assert not response.json().get('success'), \
                f"SQL injection defense failed for: {payload}"
        
        print("    ✓ SQL injection defenses working")
    
    def test_idor(self):
        """Test IDOR defenses"""
        print("\n[+] Testing IDOR defenses...")
        
        # Try to access other user's account
        response = self.session.get(f'{self.base_url}/api/account/1002')
        
        assert response.status_code == 403, "IDOR defense failed!"
        
        print("    ✓ IDOR defenses working")
    
    def test_race_condition(self):
        """Test race condition defenses"""
        print("\n[+] Testing race condition defenses...")
        
        # Get initial balance
        response = self.session.get(f'{self.base_url}/api/account/1001')
        initial_balance = response.json()['balance']
        
        # Launch simultaneous transfers
        amount = 50
        threads = 10
        results = []
        
        def transfer():
            response = self.session.post(f'{self.base_url}/api/transfer', json={
                'from_account': 1001,
                'to_account': 1002,
                'amount': amount
            })
            results.append(response.json())
        
        thread_list = [threading.Thread(target=transfer) for _ in range(threads)]
        for t in thread_list:
            t.start()
        for t in thread_list:
            t.join()
        
        # Check final balance
        time.sleep(1)
        response = self.session.get(f'{self.base_url}/api/account/1001')
        final_balance = response.json()['balance']
        
        successful = len([r for r in results if r.get('success')])
        expected_balance = initial_balance - (amount * successful)
        
        assert final_balance == expected_balance, \
            f"Race condition defense failed! Expected {expected_balance}, got {final_balance}"
        
        print("    ✓ Race condition defenses working")
    
    def test_xss(self):
        """Test XSS defenses"""
        print("\n[+] Testing XSS defenses...")
        
        payload = '<script>alert("XSS")</script>'
        
        self.session.put(f'{self.base_url}/api/profile', json={
            'full_name': payload
        })
        
        response = self.session.get(f'{self.base_url}/api/profile')
        profile = response.json()
        
        assert payload not in profile.get('full_name', ''), "XSS defense failed!"
        
        print("    ✓ XSS defenses working")
    
    def test_mass_assignment(self):
        """Test mass assignment defenses"""
        print("\n[+] Testing mass assignment defenses...")
        
        response = self.session.get(f'{self.base_url}/api/account/1001')
        initial_balance = response.json()['balance']
        
        self.session.put(f'{self.base_url}/api/profile', json={
            'email': 'test@example.com',
            'balance': 999999
        })
        
        response = self.session.get(f'{self.base_url}/api/account/1001')
        final_balance = response.json()['balance']
        
        assert final_balance == initial_balance, "Mass assignment defense failed!"
        
        print("    ✓ Mass assignment defenses working")
    
    def test_csrf(self):
        """Test CSRF defenses"""
        print("\n[+] Testing CSRF defenses...")
        
        # Try transfer without CSRF token
        response = self.session.post(f'{self.base_url}/api/transfer', json={
            'from_account': 1001,
            'to_account': 1002,
            'amount': 10
        })
        
        assert response.status_code == 403, "CSRF defense failed!"
        
        print("    ✓ CSRF defenses working")
    
    def run_all_tests(self):
        """Run all security tests"""
        print("=" * 60)
        print("SecureBank Security Test Suite")
        print("=" * 60)
        
        if not self.login():
            print("[-] Login failed! Cannot run tests.")
            return
        
        print("[+] Login successful. Running tests...\n")
        
        try:
            self.test_sql_injection()
            self.test_idor()
            self.test_race_condition()
            self.test_xss()
            self.test_mass_assignment()
            self.test_csrf()
            
            print("\n" + "=" * 60)
            print("✓ All security tests passed!")
            print("=" * 60)
            
        except AssertionError as e:
            print(f"\n✗ Test failed: {e}")
            return False
        
        return True

if __name__ == "__main__":
    suite = SecurityTestSuite('http://localhost:5002')
    suite.run_all_tests()
```

---

## Best Practices

### 1. Defense-in-Depth

- Implement multiple layers of security
- Don't rely on a single defense mechanism
- Assume one layer may fail

### 2. Secure by Default

- Start with most restrictive settings
- Explicitly allow what's needed
- Deny everything else

### 3. Least Privilege

- Grant minimum necessary permissions
- Separate read and write access
- Use service accounts with limited rights

### 4. Input Validation

- Validate on server-side (client-side is bonus)
- Use whitelists, not blacklists
- Validate type, length, format, range

### 5. Output Encoding

- Always encode output
- Encode for context (HTML, JavaScript, URL, CSS)
- Use framework protections when available

### 6. Security Testing

- Test during development
- Automated security tests in CI/CD
- Regular penetration testing
- Bug bounty program

### 7. Keep Updated

- Update dependencies regularly
- Monitor security advisories
- Patch vulnerabilities promptly

### 8. Logging and Monitoring

- Log security events
- Monitor for suspicious activity
- Alert on security incidents
- Retain logs for forensics

### 9. Code Review

- Review code for security issues
- Use security-focused code review checklists
- Automated static analysis tools
- Peer review critical code

### 10. Security Training

- Train developers on secure coding
- Stay updated on new vulnerabilities
- Learn from security incidents
- Practice on vulnerable applications (like SecureBank!)

---

## Common Mistakes to Avoid

### 1. ❌ Trusting Client-Side Validation

**Wrong:**
```javascript
// Only validating on client
if (amount > 10000) {
    alert('Amount too high!');
    return;
}
```

**Right:**
```python
# Validate on server
if amount > 10000:
    return jsonify({"error": "Amount too high"}), 400
```

### 2. ❌ Using Blacklists

**Wrong:**
```python
# Trying to block every attack
if "'" in username or "OR" in username or "--" in username:
    return error
```

**Right:**
```python
# Whitelist allowed characters
if not re.match(r'^[a-zA-Z0-9_]+$', username):
    return error
```

### 3. ❌ Rolling Your Own Crypto

**Wrong:**
```python
# Custom encryption
password = base64.b64encode(password)
```

**Right:**
```python
# Use proven libraries
from werkzeug.security import generate_password_hash
password_hash = generate_password_hash(password)
```

### 4. ❌ Exposing Stack Traces

**Wrong:**
```python
try:
    # ...
except Exception as e:
    return jsonify({"error": str(e), "traceback": traceback.format_exc()})
```

**Right:**
```python
try:
    # ...
except Exception as e:
    log_error(e, traceback.format_exc())
    return jsonify({"error": "Internal server error"}), 500
```

### 5. ❌ Hardcoding Secrets

**Wrong:**
```python
API_KEY = "sk_live_1234567890abcdef"
DB_PASSWORD = "password123"
```

**Right:**
```python
import os
API_KEY = os.environ.get('API_KEY')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
```

---

## Resources

### Documentation
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/
- CWE Top 25: https://cwe.mitre.org/top25/

### Tools
- OWASP ZAP: https://www.zaproxy.org/
- Burp Suite: https://portswigger.net/burp
- SQLMap: https://sqlmap.org/
- Bandit (Python): https://github.com/PyCQA/bandit

### Learning
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- OWASP WebGoat: https://owasp.org/www-project-webgoat/
- HackerOne CTF: https://www.hacker101.com/
- PentesterLab: https://pentesterlab.com/

---

*Security is not a product, but a process. Keep learning, keep testing, keep improving.*

*Last Updated: 2024*
