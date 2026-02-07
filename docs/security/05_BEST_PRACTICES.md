# Security Best Practices

## 🎯 Purpose

This guide provides security best practices for working with AegisForge and developing secure applications in general.

---

## 🔐 General Security Principles

### 1. Defense in Depth
Never rely on a single security control. Layer multiple protections:

- ✅ Input validation
- ✅ Output encoding
- ✅ Authentication
- ✅ Authorization
- ✅ Encryption
- ✅ Logging & monitoring

### 2. Principle of Least Privilege
Grant minimum necessary permissions:

- ✅ Database users with limited permissions
- ✅ File system access restrictions
- ✅ API scopes narrowly defined
- ✅ Container capabilities dropped

### 3. Secure by Default
Safe configuration out of the box:

- ✅ HTTPS enabled
- ✅ Debug mode disabled
- ✅ Strong secrets required
- ✅ Rate limiting enabled

### 4. Fail Securely
Handle errors without exposing sensitive information:

- ✅ Generic error messages to users
- ✅ Detailed logs in secure location
- ✅ Graceful degradation
- ✅ No stack traces in production

---

## 🛡️ Application Security

### Input Validation

**DO:**
```python
# ✅ Whitelist allowed values
ALLOWED_ROLES = ['user', 'admin', 'moderator']
if role not in ALLOWED_ROLES:
    raise ValueError("Invalid role")

# ✅ Validate data types
age = int(request.form['age'])
if not (0 <= age <= 150):
    raise ValueError("Invalid age")

# ✅ Sanitize file uploads
ALLOWED_EXTENSIONS = {'.jpg', '.png', '.pdf'}
ext = os.path.splitext(filename)[1].lower()
if ext not in ALLOWED_EXTENSIONS:
    raise ValueError("Invalid file type")
```

**DON'T:**
```python
# ❌ Trust user input
role = request.form['role']  # Could be anything!

# ❌ Blacklist (incomplete)
if 'script' in user_input:  # Can be bypassed
    raise ValueError()

# ❌ No validation
age = request.form['age']  # Could be "abc" or negative
```

### SQL Injection Prevention

**DO:**
```python
# ✅ Use parameterized queries
cursor.execute(
    "SELECT * FROM users WHERE username = ?",
    (username,)
)

# ✅ Use ORM
user = User.query.filter_by(username=username).first()
```

**DON'T:**
```python
# ❌ String concatenation
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

# ❌ String formatting
cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)
```

### XSS Prevention

**DO:**
```python
# ✅ Auto-escape in templates (Jinja2)
{{ user_input }}  # Automatically escaped

# ✅ Manual escaping
from markupsafe import escape
safe_content = escape(user_input)

# ✅ Content Security Policy
response.headers['Content-Security-Policy'] = "default-src 'self'"
```

**DON'T:**
```python
# ❌ Raw HTML output
return f"<div>{user_input}</div>"  # Dangerous!

# ❌ Unsafe template rendering
{{ user_input | safe }}  # Disables escaping
```

### Authentication & Authorization

**DO:**
```python
# ✅ Hash passwords with bcrypt/argon2
from werkzeug.security import generate_password_hash, check_password_hash
password_hash = generate_password_hash(password)

# ✅ Check authorization
if current_user.id != account.user_id:
    abort(403, "Unauthorized")

# ✅ Use secure session management
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
```

**DON'T:**
```python
# ❌ Plain text passwords
users = {'alice': 'password123'}  # Terrible!

# ❌ No authorization check
account = Account.query.get(account_id)  # IDOR vulnerability

# ❌ Insecure sessions
app.secret_key = 'weak-key'  # Predictable
```

---

## 🔑 Credential Management

### Generating Secrets

**DO:**
```python
# ✅ Cryptographically secure random
import secrets
secret_key = secrets.token_hex(32)
password = secrets.token_urlsafe(16)

# ✅ Sufficient length
# - Secret keys: 32+ bytes
# - Passwords: 12+ characters
# - API keys: 32+ characters
```

**DON'T:**
```python
# ❌ Weak random
import random
secret = random.randint(1000, 9999)  # Predictable!

# ❌ Too short
password = "pass123"  # Easily cracked
```

### Storing Secrets

**DO:**
```bash
# ✅ Environment variables
export DATABASE_PASSWORD="secure-random-value"

# ✅ Secret management services
# - AWS Secrets Manager
# - HashiCorp Vault
# - Azure Key Vault
```

**DON'T:**
```python
# ❌ Hardcoded
DB_PASSWORD = "admin123"

# ❌ In version control
# .env file committed to Git

# ❌ In configuration files
config.json with passwords
```

---

## 🌐 API Security

### Rate Limiting

**DO:**
```python
# ✅ Implement rate limiting
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/api/login')
@limiter.limit("5 per minute")
def login():
    pass
```

### CORS

**DO:**
```python
# ✅ Specific origins
CORS(app, origins=['https://example.com'])

# ✅ Credentials with specific origins
CORS(app, 
     origins=['https://example.com'],
     supports_credentials=True)
```

**DON'T:**
```python
# ❌ Wildcard with credentials
CORS(app, 
     origins='*',  # Too permissive!
     supports_credentials=True)  # Security issue!
```

---

## 📝 Logging & Monitoring

### What to Log

**DO:**
- ✅ Authentication attempts (success and failure)
- ✅ Authorization failures
- ✅ Input validation failures
- ✅ System errors
- ✅ Configuration changes

**DON'T:**
- ❌ Passwords
- ❌ Session tokens
- ❌ Credit card numbers
- ❌ Personal data (GDPR)
- ❌ API keys

### Logging Best Practices

```python
# ✅ Structured logging
import logging

logging.info(
    "Login attempt",
    extra={
        'username': username,
        'ip_address': request.remote_addr,
        'success': True
    }
)

# ❌ Don't log sensitive data
logging.info(f"Password: {password}")  # NEVER!
```

---

## 🐳 Container Security

### Dockerfile Best Practices

```dockerfile
# ✅ Use specific versions
FROM python:3.11-slim

# ✅ Don't run as root
RUN useradd -m appuser
USER appuser

# ✅ Minimal dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ✅ Read-only filesystem where possible
RUN chmod -R 555 /app

# ✅ Health checks
HEALTHCHECK CMD curl --fail http://localhost:5000/health || exit 1
```

---

## 🧪 Security Testing

### Regular Security Checks

**DO:**
- ✅ Dependency scanning (daily)
  ```bash
  pip-audit
  safety check
  ```

- ✅ Static analysis (on commit)
  ```bash
  bandit -r .
  semgrep --config=auto
  ```

- ✅ Dynamic testing (weekly)
  ```bash
  OWASP ZAP scan
  Burp Suite scan
  ```

- ✅ Penetration testing (quarterly)
  - Internal red team
  - External security firm

---

## 📚 Security Resources

### OWASP Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)

### Secure Coding Guides
- [Google Security Best Practices](https://cloud.google.com/security/best-practices)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Training Platforms
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [HackTheBox](https://www.hackthebox.com/)

---

## ✅ Security Checklist

Use this checklist for every feature:

- [ ] Input validated and sanitized
- [ ] Output properly encoded
- [ ] Authentication implemented
- [ ] Authorization checked
- [ ] Sensitive data encrypted
- [ ] Errors handled securely
- [ ] Logging configured
- [ ] Rate limiting applied
- [ ] Security headers set
- [ ] Dependencies up to date
- [ ] Code reviewed
- [ ] Security tested

---

**Last Updated:** February 2026
**Version:** 1.0
