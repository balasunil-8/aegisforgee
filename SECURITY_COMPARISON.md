# AegisForge Security Comparison Guide
## Side-by-Side: Red Team (Vulnerable) vs Blue Team (Secure)

This document provides detailed comparisons of vulnerable implementations (Red Team) versus secure implementations (Blue Team) for all major OWASP vulnerability categories.

---

## Table of Contents
1. [SQL Injection](#sql-injection)
2. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
3. [Access Control](#access-control)
4. [Authentication](#authentication)
5. [Command Injection](#command-injection)
6. [XXE (XML External Entity)](#xxe-xml-external-entity)
7. [SSRF (Server-Side Request Forgery)](#ssrf-server-side-request-forgery)
8. [Business Logic Flaws](#business-logic-flaws)
9. [Information Disclosure](#information-disclosure)
10. [Resource Consumption](#resource-consumption)

---

## SQL Injection

### ❌ Red Team (Vulnerable)
**Endpoint:** `/api/injection/sqli/boolean`

```python
@app.route('/api/injection/sqli/boolean', methods=['GET'])
def red_sqli_boolean():
    username = request.args.get('username', '')
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)  # DANGEROUS: Injectable query
    
    return jsonify({'results': results})
```

**Vulnerabilities:**
- Direct string concatenation in SQL query
- No input validation
- No parameterization
- Exposes query structure in response
- Verbose error messages reveal database information

**Attack Example:**
```bash
GET /api/injection/sqli/boolean?username=' OR '1'='1
# Returns all users regardless of username
```

### ✅ Blue Team (Secure)
**Endpoint:** `/api/blue/injection/sqli/boolean`

```python
@app.route('/api/blue/injection/sqli/boolean', methods=['GET'])
def blue_sqli_boolean():
    username = request.args.get('username', '')
    
    # Apply validation
    is_valid, error = validate_sql_input(username)
    if not is_valid:
        return {'error': 'Invalid input detected'}, 400
    
    # Use parameterized query
    query = "SELECT * FROM user WHERE username = ?"
    cursor.execute(query, (username,))
    
    return jsonify({'ok': True, 'results': results})
```

**Security Measures:**
- Input validation before processing
- Parameterized queries (prepared statements)
- No user input in query string
- Generic error messages
- Query timeout limits

**Key Takeaway:**
> Always use parameterized queries. Never concatenate user input into SQL queries.

---

## Cross-Site Scripting (XSS)

### ❌ Red Team (Vulnerable)
**Endpoint:** `/api/xss/reflected`

```python
@app.route('/api/xss/reflected', methods=['GET'])
def red_xss_reflected():
    message = request.args.get('message', 'Hello')
    
    # VULNERABLE: No output encoding
    html = f"""
    <html>
    <body>
    <h1>Your Message:</h1>
    <p>{message}</p>
    </body>
    </html>
    """
    return app.response_class(response=html, mimetype='text/html')
```

**Vulnerabilities:**
- No HTML entity encoding
- User input rendered directly in HTML
- No Content Security Policy (CSP)
- No X-XSS-Protection header

**Attack Example:**
```bash
GET /api/xss/reflected?message=<script>alert('XSS')</script>
# JavaScript executes in victim's browser
```

### ✅ Blue Team (Secure)
**Endpoint:** `/api/blue/xss/reflected`

```python
@app.route('/api/blue/xss/reflected', methods=['GET'])
def blue_xss_reflected():
    message = request.args.get('message', '')
    
    # Sanitize output
    safe_message = sanitize_xss(message)
    
    html = f"""
    <html>
    <head>{get_csp_header()}</head>
    <body>
    <h1>Message:</h1>
    <p>{safe_message}</p>
    </body>
    </html>
    """
    return app.response_class(response=html, mimetype='text/html')
```

**Security Measures:**
- HTML entity encoding via `sanitize_xss()`
- Content Security Policy (CSP) headers
- X-XSS-Protection header
- Input length validation
- Context-aware output encoding

**Key Takeaway:**
> Always encode user input before rendering in HTML. Implement CSP headers as defense-in-depth.

---

## Access Control

### ❌ Red Team (Vulnerable)
**Endpoint:** `/api/access/idor/<user_id>`

```python
@app.route('/api/access/idor/<int:user_id>', methods=['GET'])
def red_idor_access(user_id):
    # VULNERABLE: No ownership validation
    user = users_db.get(user_id)
    
    if user:
        return jsonify({
            'ok': True,
            'user': user  # Returns all data including password
        }), 200
    
    return jsonify({'error': 'User not found'}), 404
```

**Vulnerabilities:**
- No authentication required
- No ownership validation
- Returns sensitive data (passwords)
- Any user can access any user's data

**Attack Example:**
```bash
GET /api/access/idor/1
# Accesses admin user data
GET /api/access/idor/2
# Accesses other user's data
```

### ✅ Blue Team (Secure)
**Endpoint:** `/api/blue/access/idor/<user_id>`

```python
@app.route('/api/blue/access/idor/<int:user_id>', methods=['GET'])
@jwt_required()
def blue_idor_access(user_id):
    current_user_id = get_jwt_identity()
    
    # Authorization check
    if current_user_id != user_id:
        return {'error': 'Access denied'}, 403
    
    # Return only owned data, filter sensitive fields
    user = User.query.filter_by(id=user_id, id=current_user_id).first()
    if user:
        safe_data = filter_sensitive_fields(user.to_dict())
        return safe_data, 200
    
    return {'error': 'Not found'}, 404
```

**Security Measures:**
- JWT authentication required (`@jwt_required()`)
- Ownership validation before data access
- Sensitive fields filtered from response
- Consistent error messages (no user enumeration)
- Object-level authorization

**Key Takeaway:**
> Always verify object ownership. Never assume the authenticated user should access the requested resource.

---

## Authentication

### ❌ Red Team (Vulnerable)
**Endpoint:** `/api/auth/login`

```python
@app.route('/api/auth/login', methods=['POST'])
def red_login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # VULNERABLE: No rate limiting, plain text comparison
    for user_id, user in users_db.items():
        if user['username'] == username and user['password'] == password:
            token = create_access_token(identity=username)
            return jsonify({
                'ok': True,
                'token': token,
                'user': user  # VULNERABLE: Returns password
            }), 200
    
    return jsonify({'error': 'Invalid username or password'}), 401
```

**Vulnerabilities:**
- Plain text password storage
- Plain text password comparison (timing attack possible)
- No rate limiting (brute force possible)
- Returns password in response
- No account lockout
- No password complexity requirements

**Attack Example:**
```bash
# Brute force attack possible (unlimited attempts)
for password in wordlist:
    POST /api/auth/login {"username": "admin", "password": password}
```

### ✅ Blue Team (Secure)
**Endpoint:** `/api/blue/auth/login`

```python
@app.route('/api/blue/auth/login', methods=['POST'])
def blue_login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Rate limiting
    client_ip = request.remote_addr
    if not check_rate_limit(client_ip, limit=5, window=300):
        return {'error': 'Too many attempts. Try again in 5 minutes'}, 429
    
    user = User.query.filter_by(username=username).first()
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        token = create_access_token(identity=user.username)
        return {'token': token, 'user_id': user.id}, 200
    
    return {'error': 'Invalid credentials'}, 401
```

**Security Measures:**
- Bcrypt password hashing
- Constant-time comparison (bcrypt handles this)
- Rate limiting (5 attempts per 5 minutes)
- No password in response
- Account lockout after failed attempts
- Generic error messages (no username enumeration)
- Secure session management

**Key Takeaway:**
> Use bcrypt or Argon2 for password hashing. Implement rate limiting and account lockout.

---

## Command Injection

### ❌ Red Team (Vulnerable)
**Endpoint:** `/api/injection/command`

```python
@app.route('/api/injection/command', methods=['POST'])
def red_command_injection():
    data = request.get_json()
    filename = data.get('filename', 'test.txt')
    
    # VULNERABLE: Command injection via shell=True
    result = subprocess.run(f'ls -la {filename}', shell=True, 
                          capture_output=True, text=True)
    return jsonify({
        'ok': True,
        'output': result.stdout
    }), 200
```

**Vulnerabilities:**
- Uses `shell=True` allowing command chaining
- No input validation
- User input directly in command
- No command whitelist

**Attack Example:**
```bash
POST /api/injection/command
{"filename": "test.txt; cat /etc/passwd"}
# Executes: ls -la test.txt; cat /etc/passwd
```

### ✅ Blue Team (Secure)
**Endpoint:** `/api/blue/injection/command`

```python
@app.route('/api/blue/injection/command', methods=['POST'])
def blue_command_injection():
    data = request.get_json()
    command = data.get('command', '')
    
    # Command whitelist
    allowed_commands = ['ls', 'pwd', 'whoami']
    
    if command not in allowed_commands:
        return {'error': 'Command not allowed'}, 400
    
    # Safe execution without shell
    result = subprocess.run([command], capture_output=True, 
                          text=True, timeout=5)
    
    return jsonify({
        'ok': True,
        'output': result.stdout[:1000]  # Limit output
    }), 200
```

**Security Measures:**
- Command whitelist (only specific commands allowed)
- No `shell=True` (prevents command chaining)
- Array-based arguments (prevents injection)
- Timeout to prevent DoS
- Output size limiting

**Key Takeaway:**
> Never use `shell=True`. Use command whitelisting and array-based subprocess arguments.

---

## XXE (XML External Entity)

### ❌ Red Team (Vulnerable)
**Endpoint:** `/api/injection/xml-xxe`

```python
@app.route('/api/injection/xml-xxe', methods=['POST'])
def red_xml_xxe():
    xml_data = request.data.decode('utf-8')
    
    # VULNERABLE: External entities enabled
    root = ET.fromstring(xml_data)
    
    return jsonify({
        'ok': True,
        'parsed': {
            'tag': root.tag,
            'text': root.text
        }
    }), 200
```

**Vulnerabilities:**
- External entity resolution enabled
- No DTD restrictions
- Can read local files
- Can perform SSRF attacks

**Attack Example:**
```xml
POST /api/injection/xml-xxe
Content-Type: application/xml

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### ✅ Blue Team (Secure)
**Endpoint:** `/api/blue/injection/xml-xxe`

```python
@app.route('/api/blue/injection/xml-xxe', methods=['POST'])
def blue_xml_xxe():
    try:
        # Use defusedxml to prevent XXE
        from defusedxml import ElementTree as DefusedET
        xml_data = request.data.decode('utf-8')
        
        # Safe parsing with external entities disabled
        root = DefusedET.fromstring(xml_data)
        
        return jsonify({
            'ok': True,
            'parsed': {
                'tag': root.tag,
                'text': root.text
            }
        }), 200
    except Exception:
        return {'error': 'Invalid XML'}, 400
```

**Security Measures:**
- Uses `defusedxml` library
- External entities automatically disabled
- DTD processing disabled
- Entity expansion limits
- Prefer JSON over XML when possible

**Key Takeaway:**
> Use `defusedxml` library. Disable external entity resolution and DTD processing.

---

## SSRF (Server-Side Request Forgery)

### ❌ Red Team (Vulnerable)
**Endpoint:** `/api/ssrf/fetch`

```python
@app.route('/api/ssrf/fetch', methods=['POST'])
def red_ssrf():
    data = request.get_json()
    url = data.get('url', '')
    
    # VULNERABLE: No URL validation
    response = requests.get(url, timeout=5)
    return jsonify({
        'ok': True,
        'status_code': response.status_code,
        'content': response.text[:1000]
    }), 200
```

**Vulnerabilities:**
- No URL validation
- Can access internal resources (localhost, 127.0.0.1)
- Can access cloud metadata (169.254.169.254)
- Can probe internal network

**Attack Example:**
```bash
POST /api/ssrf/fetch
{"url": "http://127.0.0.1:8080/admin"}
# Accesses internal admin panel

POST /api/ssrf/fetch
{"url": "http://169.254.169.254/latest/meta-data/"}
# Accesses cloud metadata
```

### ✅ Blue Team (Secure)
**Endpoint:** `/api/blue/ssrf/fetch`

```python
@app.route('/api/blue/ssrf/fetch', methods=['POST'])
def blue_ssrf():
    data = request.get_json()
    url = data.get('url', '')
    
    # URL validation
    is_valid, error = validate_url(url)
    if not is_valid:
        return {'error': error}, 400
    
    # Additional checks for private IPs
    parsed = urlparse(url)
    if parsed.hostname in ['localhost', '127.0.0.1'] or \
       parsed.hostname.startswith('192.168.') or \
       parsed.hostname.startswith('10.') or \
       parsed.hostname == '169.254.169.254':
        return {'error': 'Private IPs not allowed'}, 403
    
    # Whitelist allowed domains
    allowed_domains = ['example.com', 'api.trusted.com']
    if parsed.hostname not in allowed_domains:
        return {'error': 'Domain not whitelisted'}, 403
    
    response = requests.get(url, timeout=5)
    return jsonify({'ok': True, 'status': response.status_code}), 200
```

**Security Measures:**
- URL format validation
- Private IP range blocking (RFC 1918)
- Localhost blocking
- Cloud metadata endpoint blocking
- Domain whitelist
- Protocol whitelist (http/https only)
- DNS rebinding protection

**Key Takeaway:**
> Block private IP ranges, localhost, and cloud metadata. Use domain whitelisting.

---

## Business Logic Flaws

### ❌ Red Team (Vulnerable)
**Endpoint:** `/api/business/coupon-stacking`

```python
@app.route('/api/business/coupon-stacking', methods=['POST'])
def red_coupon_stacking():
    data = request.get_json()
    base_price = data.get('price', 100)
    coupons = data.get('coupons', [])
    
    # VULNERABLE: No check for duplicate coupons
    discount = 0
    for coupon in coupons:
        if coupon == 'SAVE10':
            discount += base_price * 0.1
        elif coupon == 'SAVE20':
            discount += base_price * 0.2
    
    final_price = base_price - discount
    return jsonify({
        'price': base_price,
        'discount': discount,
        'final': final_price
    }), 200
```

**Vulnerabilities:**
- Multiple coupons can be applied
- Same coupon can be used multiple times
- No validation of coupon usage limits
- Can result in negative final price

**Attack Example:**
```bash
POST /api/business/coupon-stacking
{"price": 100, "coupons": ["SAVE20", "SAVE20", "SAVE20"]}
# Result: price: 100, discount: 60, final: 40 or even negative
```

### ✅ Blue Team (Secure)
**Endpoint:** `/api/blue/business/coupon-stacking`

```python
@app.route('/api/blue/business/coupon-stacking', methods=['POST'])
def blue_coupon_stacking():
    data = request.get_json()
    base_price = data.get('price', 100)
    coupons = data.get('coupons', [])
    
    # Only allow one coupon
    if len(coupons) > 1:
        return {'error': 'Only one coupon allowed per order'}, 400
    
    # Check for duplicate usage (session-based)
    if len(set(coupons)) != len(coupons):
        return {'error': 'Duplicate coupon detected'}, 400
    
    # Apply single coupon
    discount = 0
    if coupons:
        coupon = coupons[0]
        if coupon == 'SAVE10':
            discount = base_price * 0.1
        elif coupon == 'SAVE20':
            discount = base_price * 0.2
    
    final_price = max(base_price - discount, 0)  # Prevent negative
    
    return jsonify({
        'ok': True,
        'price': base_price,
        'discount': discount,
        'final': final_price
    }), 200
```

**Security Measures:**
- One coupon per order limit
- Duplicate coupon detection
- Coupon usage tracking (per session/user)
- Minimum price validation (no negative prices)
- Coupon expiration checks
- Usage limit enforcement

**Key Takeaway:**
> Validate all business rules on the server side. Prevent negative amounts and enforce usage limits.

---

## Information Disclosure

### ❌ Red Team (Vulnerable)
**Endpoint:** `/api/info/error-verbose`

```python
@app.route('/api/info/error-verbose', methods=['GET'])
def red_error_verbose():
    trigger_error = request.args.get('error', 'false') == 'true'
    
    if trigger_error:
        try:
            result = 1 / 0
        except Exception as e:
            import traceback
            return jsonify({
                'error': str(e),
                'traceback': traceback.format_exc(),  # DANGEROUS
                'vulnerability': 'Verbose error messages'
            }), 500
    
    return jsonify({'ok': True}), 200
```

**Vulnerabilities:**
- Full stack traces exposed
- Internal file paths revealed
- Library versions exposed
- Debug mode enabled
- Secret keys in responses

**Attack Example:**
```bash
GET /api/info/error-verbose?error=true
# Response reveals:
# - Internal file paths
# - Python version
# - Library versions
# - Code structure
```

### ✅ Blue Team (Secure)
**Endpoint:** `/api/blue/info/error-handling`

```python
@app.route('/api/blue/info/error-handling', methods=['GET'])
def blue_error_handling():
    trigger_error = request.args.get('error', 'false') == 'true'
    
    if trigger_error:
        try:
            result = 1 / 0
        except Exception as e:
            # Log detailed error internally
            logger.error(f"Error occurred: {str(e)}", exc_info=True)
            
            # Return generic error to user
            return jsonify({
                'error': 'An error occurred',
                'error_id': 'ERR_500',
                'message': 'Please contact support'
            }), 500
    
    return jsonify({'ok': True}), 200
```

**Security Measures:**
- Generic error messages for users
- Detailed errors logged internally only
- No stack traces in responses
- Error IDs for support tracking
- Debug mode disabled in production
- Version numbers hidden

**Key Takeaway:**
> Never expose internal details in error messages. Log detailed errors internally, show generic messages to users.

---

## Resource Consumption

### ❌ Red Team (Vulnerable)
**Endpoint:** `/api/resource/unlimited-results`

```python
@app.route('/api/resource/unlimited-results', methods=['GET'])
def red_unlimited_results():
    # VULNERABLE: Returns all records
    users = User.query.all()  # Could be millions
    return jsonify({
        'users': [u.to_dict() for u in users],
        'count': len(users)
    }), 200
```

**Vulnerabilities:**
- No pagination
- Can return millions of records
- Memory exhaustion possible
- DoS attack vector
- No rate limiting

**Attack Example:**
```bash
GET /api/resource/unlimited-results
# Server loads all users into memory, causing DoS
```

### ✅ Blue Team (Secure)
**Endpoint:** `/api/blue/resource/pagination`

```python
@app.route('/api/blue/resource/pagination', methods=['GET'])
def blue_resource_pagination():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)  # Max 100
    
    # Validate pagination parameters
    if page < 1:
        return {'error': 'Invalid page number'}, 400
    if per_page < 1 or per_page > 100:
        return {'error': 'per_page must be between 1 and 100'}, 400
    
    users = User.query.paginate(page=page, per_page=per_page)
    
    return jsonify({
        'ok': True,
        'users': [u.to_dict() for u in users.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': users.total,
            'pages': users.pages
        }
    }), 200
```

**Security Measures:**
- Mandatory pagination
- Maximum page size limit (100 items)
- Input validation on pagination parameters
- Rate limiting on endpoint
- Database query timeout
- Connection pooling

**Key Takeaway:**
> Always implement pagination. Set maximum limits on results and enforce rate limiting.

---

## Summary

| Category | Red Team Vulnerability | Blue Team Protection |
|----------|----------------------|---------------------|
| SQL Injection | String concatenation | Parameterized queries |
| XSS | No output encoding | HTML entity encoding + CSP |
| Access Control | No ownership check | Object-level authorization |
| Authentication | Plain text passwords | Bcrypt + rate limiting |
| Command Injection | shell=True | Command whitelist |
| XXE | External entities enabled | defusedxml library |
| SSRF | No URL validation | Private IP blocking + whitelist |
| Business Logic | No validation | Server-side validation |
| Info Disclosure | Verbose errors | Generic error messages |
| Resource Consumption | No pagination | Pagination + limits |

---

## Best Practices Summary

1. **Input Validation**: Validate all user input on the server side
2. **Output Encoding**: Encode all output based on context (HTML, URL, JavaScript)
3. **Authentication**: Use strong password hashing (bcrypt/Argon2) + MFA
4. **Authorization**: Validate object ownership and permissions
5. **Error Handling**: Generic messages to users, detailed logs internally
6. **Rate Limiting**: Implement on all sensitive endpoints
7. **Secure Defaults**: Disable debug mode, use secure session settings
8. **Defense in Depth**: Multiple layers of security controls
9. **Least Privilege**: Grant minimum necessary permissions
10. **Security Headers**: Implement CSP, HSTS, X-Frame-Options, etc.

---

## Testing Your Implementation

Use AegisForge's dual-mode architecture to test both implementations:

```bash
# Start comparison mode
python aegisforge_modes.py compare

# Test Red Team (vulnerable)
curl http://localhost:5000/api/injection/sqli/boolean?username=' OR '1'='1

# Test Blue Team (secure)
curl http://localhost:5001/api/blue/injection/sqli/boolean?username=' OR '1'='1
```

---

**For more information, see:**
- [README.md](README.md) - Main documentation
- [TOOL_INTEGRATION_README.md](TOOL_INTEGRATION_README.md) - Testing tools guide
- [API_DOCUMENTATION.md](API_DOCUMENTATION.md) - Complete API reference
