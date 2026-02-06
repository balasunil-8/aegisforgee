# Authentication Labs - Postman Testing Guide

## 🎯 What You'll Learn

Authentication is how websites know who you are. Think of it like showing your ID card to get into a building. In this lab, you'll learn how hackers break authentication systems and how to find these bugs using Postman.

**Topics Covered:**
- Password attacks and brute force testing
- JWT token manipulation and forgery
- Session hijacking and fixation
- Multi-factor authentication (MFA) bypass
- Password reset vulnerabilities
- OAuth and API authentication flaws

## 💰 Real-World Bug Bounty Examples

### Example 1: JWT Algorithm Confusion - $10,000
**Company:** Major social media platform  
**Vulnerability:** JWT tokens could be modified by changing the algorithm from RS256 (secure) to HS256 (weak)  
**Impact:** Attackers could create valid tokens for any user account  
**Payout:** $10,000

**How it worked:** The application accepted both RS256 and HS256 algorithms. Hackers changed the algorithm to HS256 and signed the token with the public key, creating fake admin tokens.

### Example 2: Password Reset Token Leak - $15,000
**Company:** E-commerce giant  
**Vulnerability:** Password reset tokens were included in the Referer header  
**Impact:** Account takeover of any user  
**Payout:** $15,000

**How it worked:** When users clicked password reset links and then visited external sites, the reset token leaked through the Referer header, allowing attackers to reset victims' passwords.

### Example 3: Session Fixation - $8,500
**Company:** Online banking platform  
**Vulnerability:** Session IDs didn't change after login  
**Impact:** Attackers could hijack user sessions  
**Payout:** $8,500

**How it worked:** Attackers generated a session ID, sent it to victims in a phishing link, and after the victim logged in, the attacker could use that same session ID to access the account.

### Example 4: Multi-Factor Authentication Bypass - $20,000
**Company:** Cloud storage provider  
**Vulnerability:** MFA could be bypassed by manipulating API requests  
**Impact:** Complete account takeover despite MFA  
**Payout:** $20,000

**How it worked:** The application checked MFA on the login page but not on the API endpoint. Attackers could skip MFA by directly calling the API endpoint.

### Example 5: OAuth Token Not Expiring - $12,000
**Company:** Social networking site  
**Vulnerability:** OAuth tokens never expired, even after password changes  
**Impact:** Permanent account access  
**Payout:** $12,000

**How it worked:** Once an attacker obtained an OAuth token, it remained valid forever. Even if users changed passwords, old tokens still worked.

### Example 6: Weak Password Policy - $5,000
**Company:** Healthcare provider  
**Vulnerability:** No rate limiting on password attempts  
**Impact:** Brute force attacks were possible  
**Payout:** $5,000

**How it worked:** The application allowed unlimited password attempts without lockouts or CAPTCHAs, making it easy to guess passwords.

## 🔐 Understanding Authentication Types

### 1. Session-Based Authentication
When you log in, the server gives you a "ticket" (session ID). You show this ticket with every request.

**Flow:**
1. User sends username + password
2. Server validates and creates session
3. Server sends session ID in cookie
4. Client includes cookie in future requests

### 2. Token-Based Authentication (JWT)
Instead of a ticket, you get a "badge" that contains your information. The badge is signed so it can't be faked.

**JWT Structure:**
```
header.payload.signature
eyJhbGci.eyJ1c2Vy.SflKxwRJ
```

**Parts:**
- **Header:** Algorithm used (RS256, HS256)
- **Payload:** User data (user ID, role, expiration)
- **Signature:** Proof the token hasn't been tampered with

### 3. OAuth 2.0
Like letting someone borrow your library card temporarily. You give permission, but they can't change your account.

## 🧪 Lab 1: Brute Force Testing

### What is Brute Force?
Trying many passwords until you find the right one. Like trying every combination on a lock.

### Testing with Postman

**Step 1: Set Up Your Request**

```
POST http://localhost:5000/api/auth/login
Content-Type: application/json

{
    "username": "admin",
    "password": "{{password}}"
}
```

**Step 2: Create a Password List**

Create a CSV file named `passwords.csv`:
```csv
password
123456
password
12345678
qwerty
abc123
monkey
1234567
letmein
trustno1
dragon
```

**Step 3: Configure Collection Runner**

1. Click "Runner" in Postman
2. Select your collection
3. Choose "Data" and upload passwords.csv
4. Set iterations to 10 (or number of passwords)
5. Run

**Step 4: Analyze Results**

Look for:
- ✅ **200 OK** - Password found!
- ❌ **401 Unauthorized** - Wrong password
- ⚠️ **429 Too Many Requests** - Rate limiting working (good security!)

### Testing Rate Limiting

**Good Security Response:**
```json
{
    "error": "Too many login attempts",
    "retry_after": 300,
    "locked_until": "2024-01-15T10:30:00Z"
}
```

### Practice Exercise 1

**Mission:** Test if the login endpoint has rate limiting.

1. Send 10 login requests with wrong passwords
2. Check if you get blocked
3. Document how many attempts are allowed
4. Note if there's a lockout period

**Expected Results:**
- Good app: Blocks after 3-5 attempts
- Bad app: Allows unlimited attempts

## 🎫 Lab 2: JWT Token Manipulation

### Understanding JWT Tokens

**Decode a JWT Token:**

Use jwt.io or Postman's built-in decoder:

```javascript
// In Postman Tests tab
const token = pm.response.json().token;
const parts = token.split('.');
const payload = JSON.parse(atob(parts[1]));
console.log('User ID:', payload.userId);
console.log('Role:', payload.role);
console.log('Expires:', payload.exp);
```

### Test 1: Algorithm Confusion Attack

**Vulnerability:** App accepts multiple signing algorithms.

**Step 1: Get a Valid Token**

```
POST http://localhost:5000/api/auth/login
Content-Type: application/json

{
    "username": "regularuser",
    "password": "password123"
}
```

**Step 2: Decode the Token**

Original token payload:
```json
{
    "userId": 42,
    "username": "regularuser",
    "role": "user",
    "exp": 1705334400
}
```

**Step 3: Modify the Token**

Change the header algorithm from RS256 to HS256:

```json
{
    "alg": "HS256",
    "typ": "JWT"
}
```

Change the payload to admin:
```json
{
    "userId": 1,
    "username": "admin",
    "role": "admin",
    "exp": 1705334400
}
```

**Step 4: Re-sign the Token**

Use a script to sign with the public key:

```javascript
// In Postman Pre-request Script
const header = btoa(JSON.stringify({"alg":"HS256","typ":"JWT"}));
const payload = btoa(JSON.stringify({
    "userId": 1,
    "username": "admin",
    "role": "admin",
    "exp": Math.floor(Date.now() / 1000) + 3600
}));

// Sign with public key (in real attack)
const signature = "fake_signature";
const token = header + "." + payload + "." + signature;
pm.environment.set("manipulated_token", token);
```

**Step 5: Test the Modified Token**

```
GET http://localhost:5000/api/auth/admin/users
Authorization: Bearer {{manipulated_token}}
```

### Test 2: Token Expiration Testing

**Check if expired tokens are rejected:**

```javascript
// Pre-request Script - Create expired token
const oldDate = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
pm.environment.set("token_exp", oldDate);
```

**Request:**
```
GET http://localhost:5000/api/auth/profile
Authorization: Bearer {{expired_token}}
```

**Expected Response:**
```json
{
    "error": "Token expired",
    "expired_at": "2024-01-15T09:00:00Z"
}
```

### Test 3: Token Signature Validation

**Remove or modify the signature:**

```javascript
// Pre-request Script
const token = pm.environment.get("auth_token");
const parts = token.split('.');
const tampered = parts[0] + '.' + parts[1] + '.tampered_signature';
pm.environment.set("tampered_token", tampered);
```

**Expected Result:**
- ✅ Good app: Rejects with "Invalid signature"
- ❌ Bad app: Accepts modified token

### Practice Exercise 2

**Mission:** Find token vulnerabilities.

Tasks:
1. Decode your JWT token and examine the payload
2. Try to extend the expiration time
3. Try to change your role from "user" to "admin"
4. Try to remove the signature completely
5. Document which attacks work

## 🔄 Lab 3: Session Hijacking

### What is Session Hijacking?
Stealing someone's session ID to impersonate them. Like stealing someone's movie ticket to get into the theater.

### Test 1: Session ID in URL

**Vulnerable Pattern:**
```
http://localhost:5000/api/dashboard?sessionid=abc123xyz
```

**Test:**
1. Log in and get session ID
2. Copy the session ID
3. Open incognito/private window
4. Use the copied session ID
5. Check if you're logged in

**Script:**
```javascript
// Extract session ID from response
const sessionId = pm.response.json().sessionId;
pm.environment.set("stolen_session", sessionId);

// Use in another request
GET http://localhost:5000/api/profile?sessionid={{stolen_session}}
```

### Test 2: Session Fixation

**Vulnerability:** Session ID doesn't change after login.

**Testing Steps:**

1. **Before Login - Get Session ID:**
```
GET http://localhost:5000/api/auth/init
```

Save the session ID: `sess_123456789`

2. **Login with Fixed Session:**
```
POST http://localhost:5000/api/auth/login
Cookie: session_id=sess_123456789

{
    "username": "victim",
    "password": "password"
}
```

3. **Test if Old Session Still Works:**
```
GET http://localhost:5000/api/profile
Cookie: session_id=sess_123456789
```

**Expected Behavior:**
- ✅ Good app: New session ID after login
- ❌ Bad app: Same session ID before and after

### Test 3: Session Timeout

**Test if sessions expire properly:**

```javascript
// Pre-request Script
const loginTime = pm.environment.get("login_time");
const now = Date.now();
const elapsed = (now - loginTime) / 1000 / 60; // minutes
console.log("Session age:", elapsed, "minutes");
```

**Wait 30 minutes, then:**
```
GET http://localhost:5000/api/profile
Authorization: Bearer {{old_token}}
```

**Expected:**
- ✅ Good app: Session expired error
- ❌ Bad app: Session still valid

### Practice Exercise 3

**Mission:** Test session security.

1. Check if session IDs are predictable
2. Test if sessions expire after logout
3. Check if multiple sessions can exist
4. Test if sessions survive password changes

## 🔒 Lab 4: Password Reset Vulnerabilities

### Test 1: Token Prediction

**Weak Pattern:**
```
Reset token: user42_20240115_1430
```

**Test:**
```
POST http://localhost:5000/api/auth/reset-password
Content-Type: application/json

{
    "token": "user43_20240115_1430",
    "newPassword": "hacked123"
}
```

### Test 2: Token Reuse

**Steps:**

1. **Request Reset:**
```
POST http://localhost:5000/api/auth/forgot-password
Content-Type: application/json

{
    "email": "victim@example.com"
}
```

2. **Use Token Once:**
```
POST http://localhost:5000/api/auth/reset-password
Content-Type: application/json

{
    "token": "abc123xyz",
    "newPassword": "newpass123"
}
```

3. **Try to Reuse Token:**
```
POST http://localhost:5000/api/auth/reset-password
Content-Type: application/json

{
    "token": "abc123xyz",
    "newPassword": "hacked456"
}
```

**Expected:**
- ✅ Good app: Token invalid after first use
- ❌ Bad app: Token can be reused

### Test 3: Token Leak via Referer

**Set up a test:**

1. Get password reset link
2. In Postman, add this header:
```
Referer: http://attacker.com/steal.php
```

3. Check server logs or monitor network for token leak

### Practice Exercise 4

**Mission:** Find password reset flaws.

1. Request a password reset
2. Try to reuse the reset token
3. Check if tokens expire
4. Test rate limiting on reset requests
5. Try to reset another user's password

## 🛡️ Lab 5: Multi-Factor Authentication (MFA) Bypass

### Test 1: Direct Endpoint Access

**Login Flow:**
```
1. POST /api/auth/login → Returns "MFA Required"
2. POST /api/auth/mfa/verify → Validates MFA code
3. GET /api/profile → User data
```

**Bypass Test - Skip Step 2:**

```
POST http://localhost:5000/api/auth/login
Content-Type: application/json

{
    "username": "user",
    "password": "password"
}

// Then immediately:
GET http://localhost:5000/api/profile
Authorization: Bearer {{partial_token}}
```

**Expected:**
- ✅ Good app: Requires MFA verification
- ❌ Bad app: Grants access without MFA

### Test 2: Response Manipulation

**Intercept and modify MFA response:**

Original response:
```json
{
    "mfa_required": true,
    "mfa_verified": false,
    "partial_token": "xyz"
}
```

**Modified response (if intercepted):**
```json
{
    "mfa_required": false,
    "mfa_verified": true,
    "token": "xyz"
}
```

### Test 3: MFA Code Brute Force

**Test rate limiting on MFA codes:**

```javascript
// Collection Runner with MFA codes
// codes.csv:
code
000000
111111
123456
654321
```

```
POST http://localhost:5000/api/auth/mfa/verify
Content-Type: application/json

{
    "partial_token": "xyz",
    "code": "{{code}}"
}
```

**Expected:**
- ✅ Good app: Locks after 3-5 attempts
- ❌ Bad app: Allows unlimited attempts

### Practice Exercise 5

**Mission:** Test MFA implementation.

1. Check if MFA can be bypassed
2. Test if backup codes work after being used
3. Try to brute force MFA codes
4. Check if MFA resets after password change

## 🔧 Lab 6: OAuth 2.0 Testing

### Test 1: Redirect URI Manipulation

**Original OAuth flow:**
```
https://oauth.provider.com/authorize?
  client_id=123&
  redirect_uri=https://aegisforge.com/callback&
  response_type=code
```

**Attack - Change redirect_uri:**
```
https://oauth.provider.com/authorize?
  client_id=123&
  redirect_uri=https://attacker.com/steal&
  response_type=code
```

**Testing in Postman:**

```
GET http://localhost:5000/api/auth/oauth/authorize
Parameters:
  client_id: aegisforge_app
  redirect_uri: http://attacker.com/callback
  response_type: code
```

**Expected:**
- ✅ Good app: Validates redirect URI
- ❌ Bad app: Allows arbitrary redirects

### Test 2: State Parameter Missing

**Vulnerability:** No CSRF protection in OAuth flow.

**Test without state parameter:**
```
GET http://localhost:5000/api/auth/oauth/callback
Parameters:
  code: abc123
  // Missing: state parameter
```

**Expected:**
- ✅ Good app: Rejects without state
- ❌ Bad app: Accepts without state

### Test 3: Token Scope Escalation

**Request limited scope:**
```
GET http://localhost:5000/api/auth/oauth/authorize
Parameters:
  scope: read_profile
```

**Then try to access admin functions:**
```
GET http://localhost:5000/api/auth/admin/users
Authorization: Bearer {{limited_scope_token}}
```

**Expected:**
- ✅ Good app: Denies access (insufficient scope)
- ❌ Bad app: Grants access

## 📋 Comprehensive Testing Checklist

### Authentication Testing

- [ ] Test brute force protection
- [ ] Verify account lockout policy
- [ ] Check password complexity requirements
- [ ] Test password history (can't reuse old passwords)
- [ ] Verify secure password storage (hashed, not plain text)

### Token Testing

- [ ] Verify JWT signature validation
- [ ] Test token expiration
- [ ] Check for algorithm confusion vulnerabilities
- [ ] Test token revocation after logout
- [ ] Verify tokens expire after password change

### Session Testing

- [ ] Check session ID randomness
- [ ] Verify session expiration
- [ ] Test concurrent session limits
- [ ] Check session fixation protection
- [ ] Test session hijacking resistance

### Password Reset Testing

- [ ] Verify token unpredictability
- [ ] Test token expiration (should expire in 15-60 min)
- [ ] Check one-time use enforcement
- [ ] Test rate limiting on reset requests
- [ ] Verify tokens invalidate after use

### MFA Testing

- [ ] Test MFA bypass attempts
- [ ] Verify backup code security
- [ ] Check MFA code expiration
- [ ] Test rate limiting on MFA attempts
- [ ] Verify MFA required for sensitive actions

## 🛠️ Practice Exercise: Complete Security Audit

**Mission:** Perform a full authentication audit of AegisForge.

### Phase 1: Reconnaissance (15 minutes)

1. Identify all authentication endpoints
2. Document authentication flows
3. List all token types used
4. Map session management approach

**Endpoints to test:**
```
POST /api/auth/register
POST /api/auth/login
POST /api/auth/logout
POST /api/auth/forgot-password
POST /api/auth/reset-password
GET /api/auth/profile
PUT /api/auth/change-password
POST /api/auth/mfa/enable
POST /api/auth/mfa/verify
GET /api/auth/oauth/authorize
POST /api/auth/oauth/token
```

### Phase 2: Vulnerability Testing (45 minutes)

Create a Postman collection with these tests:

1. **Brute Force Test Suite**
   - Login attempts without rate limiting
   - MFA code guessing
   - Password reset token guessing

2. **Token Manipulation Suite**
   - JWT algorithm confusion
   - Token signature tampering
   - Expiration time modification
   - Role escalation via token

3. **Session Security Suite**
   - Session fixation
   - Session hijacking
   - Concurrent sessions
   - Session timeout

4. **Password Reset Suite**
   - Token prediction
   - Token reuse
   - Rate limiting
   - Cross-account reset

5. **MFA Bypass Suite**
   - Direct endpoint access
   - Response manipulation
   - Backup code abuse

### Phase 3: Reporting (30 minutes)

Create a security report with:

**Report Template:**

```markdown
# Authentication Security Audit Report

## Executive Summary
- Total vulnerabilities found: X
- Critical: X
- High: X  
- Medium: X
- Low: X

## Detailed Findings

### Finding 1: [Vulnerability Name]
**Severity:** Critical/High/Medium/Low
**Endpoint:** /api/auth/xyz
**Description:** [What's wrong]
**Impact:** [What attacker can do]
**Reproduction Steps:**
1. Step one
2. Step two
3. Step three

**Evidence:**
[Screenshots or Postman response]

**Recommendation:**
[How to fix it]

## Positive Findings
[Security features that work well]

## Overall Risk Score
[Low/Medium/High]
```

## 🏆 Secure Implementation Examples

### Secure Login Endpoint

```python
from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash
import jwt
import datetime
import redis
from functools import wraps

app = Flask(__name__)
redis_client = redis.Redis(host='localhost', port=6379)

# Rate limiting decorator
def rate_limit(max_attempts=5, window=300):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get IP address
            ip = request.remote_addr
            key = f"rate_limit:{ip}:{request.endpoint}"
            
            # Check attempts
            attempts = redis_client.get(key)
            if attempts and int(attempts) >= max_attempts:
                return jsonify({
                    "error": "Too many attempts",
                    "retry_after": redis_client.ttl(key)
                }), 429
            
            # Increment counter
            redis_client.incr(key)
            redis_client.expire(key, window)
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/api/auth/login', methods=['POST'])
@rate_limit(max_attempts=5, window=300)
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Get user from database
    user = get_user_by_username(username)
    
    if not user:
        # Don't reveal if user exists
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Check if account is locked
    lock_key = f"account_lock:{user.id}"
    if redis_client.get(lock_key):
        return jsonify({
            "error": "Account locked",
            "reason": "Too many failed attempts"
        }), 403
    
    # Verify password
    if not check_password_hash(user.password_hash, password):
        # Increment failed attempts
        fail_key = f"failed_login:{user.id}"
        fails = redis_client.incr(fail_key)
        redis_client.expire(fail_key, 600)  # 10 minutes
        
        if fails >= 5:
            # Lock account
            redis_client.setex(lock_key, 1800, "1")  # 30 min lock
            return jsonify({
                "error": "Account locked due to failed attempts"
            }), 403
        
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Clear failed attempts on success
    redis_client.delete(f"failed_login:{user.id}")
    
    # Generate secure JWT token
    token = jwt.encode({
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'iat': datetime.datetime.utcnow(),
        'jti': generate_unique_token_id()  # JWT ID for revocation
    }, app.config['JWT_SECRET'], algorithm='RS256')
    
    # Store session
    session_key = f"session:{user.id}:{token_id}"
    redis_client.setex(session_key, 3600, token)
    
    return jsonify({
        "token": token,
        "expires_in": 3600,
        "token_type": "Bearer"
    }), 200
```

### Secure Password Reset

```python
import secrets
import hashlib

@app.route('/api/auth/forgot-password', methods=['POST'])
@rate_limit(max_attempts=3, window=900)  # 3 per 15 min
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    
    # Always return same response (don't leak user existence)
    response = {
        "message": "If account exists, reset link sent"
    }
    
    user = get_user_by_email(email)
    if not user:
        # Still return success to prevent email enumeration
        return jsonify(response), 200
    
    # Generate cryptographically secure token
    reset_token = secrets.token_urlsafe(32)
    
    # Hash token before storing
    token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
    
    # Store token with metadata
    reset_data = {
        'user_id': user.id,
        'email': email,
        'created_at': datetime.datetime.utcnow().isoformat(),
        'ip_address': request.remote_addr
    }
    
    # Token expires in 15 minutes
    redis_client.setex(
        f"reset_token:{token_hash}",
        900,  # 15 minutes
        json.dumps(reset_data)
    )
    
    # Send email (not shown)
    send_reset_email(email, reset_token)
    
    return jsonify(response), 200

@app.route('/api/auth/reset-password', methods=['POST'])
@rate_limit(max_attempts=5, window=900)
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    
    # Hash token to lookup
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # Get token data
    reset_data = redis_client.get(f"reset_token:{token_hash}")
    if not reset_data:
        return jsonify({"error": "Invalid or expired token"}), 400
    
    reset_info = json.loads(reset_data)
    
    # Validate password strength
    if not is_strong_password(new_password):
        return jsonify({
            "error": "Password too weak",
            "requirements": [
                "At least 12 characters",
                "Contains uppercase letter",
                "Contains lowercase letter",
                "Contains number",
                "Contains special character"
            ]
        }), 400
    
    # Update password
    user = get_user_by_id(reset_info['user_id'])
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    
    # Invalidate token (one-time use)
    redis_client.delete(f"reset_token:{token_hash}")
    
    # Invalidate all user sessions
    invalidate_all_user_sessions(user.id)
    
    # Log security event
    log_security_event('password_reset', user.id, request.remote_addr)
    
    return jsonify({"message": "Password reset successful"}), 200
```

### Secure JWT Validation

```python
def validate_jwt_token(token):
    try:
        # Decode with strict validation
        payload = jwt.decode(
            token,
            app.config['JWT_PUBLIC_KEY'],
            algorithms=['RS256'],  # Only allow RS256
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_iat': True,
                'require_exp': True,
                'require_iat': True
            }
        )
        
        # Check if token is revoked
        jti = payload.get('jti')
        if redis_client.get(f"revoked_token:{jti}"):
            raise ValueError("Token revoked")
        
        # Check if user still exists and is active
        user = get_user_by_id(payload['user_id'])
        if not user or not user.is_active:
            raise ValueError("User invalid")
        
        # Check if password changed after token issued
        token_iat = datetime.datetime.fromtimestamp(payload['iat'])
        if user.password_changed_at > token_iat:
            raise ValueError("Token invalidated by password change")
        
        return payload
        
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")
```

## 📚 Additional Resources

### Tools
- **JWT.io** - Decode and verify JWT tokens
- **Burp Suite** - Intercept and modify authentication requests
- **OWASP ZAP** - Automated authentication testing
- **Postman Interceptor** - Capture browser authentication flows

### Learning Resources
- **OWASP Authentication Cheat Sheet** - Best practices
- **PortSwigger Web Security Academy** - Interactive labs
- **HackerOne Disclosed Reports** - Real-world examples
- **Bug Bounty Platforms** - Practice on real applications

### Common Vulnerabilities
- **CWE-287:** Improper Authentication
- **CWE-798:** Use of Hard-coded Credentials
- **CWE-640:** Weak Password Recovery
- **CWE-384:** Session Fixation
- **CWE-306:** Missing Authentication

## 🎓 Key Takeaways

1. **Always use rate limiting** - Prevent brute force attacks
2. **Validate JWT signatures strictly** - Don't trust client data
3. **Rotate session IDs after login** - Prevent fixation attacks
4. **Make reset tokens unpredictable** - Use cryptographic random
5. **Expire tokens and sessions** - Limit attack window
6. **Enforce strong passwords** - Make guessing harder
7. **Log authentication events** - Detect attacks early
8. **Use secure algorithms** - RS256 for JWT, bcrypt for passwords
9. **Never reveal user existence** - Prevent enumeration
10. **Test everything with Postman** - Automate security testing

## 🚀 Next Steps

1. Complete all practice exercises in this guide
2. Create your own authentication test collection
3. Test real applications (with permission only!)
4. Read bug bounty reports to learn new techniques
5. Practice on HackTheBox and TryHackMe
6. Move on to **10_AUTHORIZATION_LABS.md**

---

**Remember:** Only test applications you own or have explicit permission to test. Unauthorized testing is illegal and unethical.

**Happy Hacking!** 🔐
