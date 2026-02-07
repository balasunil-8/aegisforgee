# Credential Management Guide

## 🔐 Purpose

This guide explains how credentials are managed in AegisForge, the difference between test and production credentials, and best practices for credential security.

---

## 🎓 Understanding Credential Types

### 1. Test Credentials (Educational)

**Purpose:** Educational demonstrations and easy setup

**Characteristics:**
- Hardcoded in source code (intentionally)
- Publicly documented
- Used for Red Team vulnerable endpoints
- NOT real secrets

**Examples:**
```python
# backend/apps/securebank/seed_data.py
users = [
    ('alice', 'password123', 'alice@example.com'),
    ('bob', 'securepass456', 'bob@example.com'),
    ('admin', 'admin123', 'admin@aegisbank.com'),
]
```

**Why hardcoded?**
1. Instant setup for learners
2. Consistent across workshops
3. Demonstrates insecure practices
4. Educational value

### 2. Demo Credentials (OWASP A05)

**Purpose:** Demonstrate security misconfiguration vulnerabilities

**Examples:**
```python
DEFAULT_USERS = {
    'admin': {'username': 'admin', 'password': 'admin'},
    'root': {'username': 'root', 'password': 'root'},
}
```

**Location:** `backend/owasp/web_2021/a05_misconfiguration_red.py`

### 3. Production Credentials

**Purpose:** Real deployments (if ever needed)

**Characteristics:**
- MUST be environment variables
- Generated randomly
- Strong and unique
- Never committed to code

---

## 📋 Test Credentials Reference

### SecureBank Users

| Username | Password | Role | Accounts |
|----------|----------|------|----------|
| alice | password123 | user | Checking, Savings |
| bob | securepass456 | user | Checking, Savings |
| admin | admin123 | admin | N/A |
| carol | carol789 | user | Checking, Savings |

### OWASP A05 Demo

| Username | Password | Role |
|----------|----------|------|
| admin | admin | administrator |
| root | root | administrator |
| test | test123 | user |
| guest | guest | guest |

**All credentials are in `/CREDENTIALS.md`**

---

## 🔧 Using Environment Variables

### Development Setup

**Step 1:** Copy environment template
```bash
cp .env.example .env
```

**Step 2:** Customize credentials
```bash
# Edit .env
nano .env
```

**Step 3:** Set custom passwords
```bash
TEST_USER_ALICE_PASSWORD=mycustompassword
TEST_USER_BOB_PASSWORD=anothercustompass
TEST_USER_ADMIN_PASSWORD=adminpassword
```

**Step 4:** Credentials are automatically loaded
```python
# config.py
ALICE_PASSWORD = os.environ.get('TEST_USER_ALICE_PASSWORD', 'password123')
```

### Production Setup (Not Recommended)

**AegisForge is for education, not production!**

If you must deploy:

**Step 1:** Generate strong passwords
```python
import secrets
print(secrets.token_hex(16))
```

**Step 2:** Set environment variables
```bash
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export TEST_USER_ALICE_PASSWORD="strong-random-password-here"
```

**Step 3:** Disable Red Team endpoints

**Step 4:** Use only Blue Team endpoints

---

## 🛠️ Credential Management Utilities

### Using SecretManager

```python
from backend.utils.secrets_manager import SecretManager

# Initialize
sm = SecretManager()

# Generate secret key
secret_key = sm.generate_secret_key(32)

# Generate password
password = sm.generate_password(16)

# Hash password
password_hash = sm.hash_password('mypassword')

# Get test credentials
test_creds = sm.get_test_credentials()
print(test_creds['alice'])  # From environment or default
```

### Using EnvironmentLoader

```python
from backend.utils.env_loader import EnvironmentLoader

# Load environment variables
env = EnvironmentLoader('.env')

# Get string value
secret_key = env.get_str('FLASK_SECRET_KEY', required=True)

# Get boolean value
debug = env.get_bool('FLASK_DEBUG', default=False)

# Get integer value
session_lifetime = env.get_int('PERMANENT_SESSION_LIFETIME', default=3600)

# Get list value
cors_origins = env.get_list('CORS_ORIGINS')
```

---

## 🔒 Security Best Practices

### DO:
- ✅ Use environment variables for ALL secrets
- ✅ Generate cryptographically secure random values
- ✅ Rotate credentials regularly
- ✅ Use different credentials per environment
- ✅ Hash passwords with bcrypt/argon2
- ✅ Never log credentials
- ✅ Use secret management tools (Vault, AWS Secrets Manager)

### DO NOT:
- ❌ Hardcode credentials (except for educational demos)
- ❌ Commit `.env` files to version control
- ❌ Share credentials via email or chat
- ❌ Use weak passwords
- ❌ Reuse credentials across services
- ❌ Store credentials in plain text
- ❌ Use default credentials in production

---

## 📖 Real-World Examples

### Bad: Hardcoded in Production
```python
# ❌ NEVER DO THIS IN PRODUCTION
app.secret_key = 'insecure-key-123'
db_password = 'admin123'
api_key = 'sk_test_abc123'
```

### Good: Environment Variables
```python
# ✅ DO THIS
import os
import secrets

app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
db_password = os.environ['DATABASE_PASSWORD']
api_key = os.environ['API_KEY']
```

### Better: Secret Management Service
```python
# ✅ EVEN BETTER (for production)
from secret_manager import get_secret

app.secret_key = get_secret('flask-secret-key')
db_password = get_secret('database-password')
api_key = get_secret('api-key')
```

---

## 🧪 Testing Credential Management

### Test 1: Environment Variables Load Correctly
```python
# test_credentials.py
import os
from backend.config import TestCredentials

# Check if custom value is used
os.environ['TEST_USER_ALICE_PASSWORD'] = 'custom123'
creds = TestCredentials()
assert creds.ALICE_PASSWORD == 'custom123'
print("✅ Environment variables work!")
```

### Test 2: Secrets Are Generated Securely
```python
from backend.utils.secrets_manager import SecretManager

sm = SecretManager()
secret1 = sm.generate_secret_key(32)
secret2 = sm.generate_secret_key(32)

assert len(secret1) == 64  # 32 bytes = 64 hex chars
assert secret1 != secret2  # Should be unique
print("✅ Secret generation works!")
```

---

## 🚨 Common Mistakes

### Mistake 1: Using Defaults in Production
```python
# ❌ BAD
password = os.environ.get('PASSWORD', 'admin123')  # Default is weak!
```

### Mistake 2: Committing .env Files
```bash
# ❌ BAD
git add .env  # NEVER DO THIS!
```

### Mistake 3: Hardcoding Without Comments
```python
# ❌ BAD
secret = 'abc123'  # No warning this is educational only
```

### Correct Approach
```python
# ✅ GOOD
password = os.environ.get('PASSWORD')  # No default
if not password:
    raise ValueError("PASSWORD environment variable required!")
```

---

## 📚 Related Documentation

- `/SECURITY.md` - Security policy
- `/CREDENTIALS.md` - All test credentials
- `01_ENVIRONMENT_SETUP.md` - Environment setup
- `05_BEST_PRACTICES.md` - Security best practices

---

**Last Updated:** February 2026
