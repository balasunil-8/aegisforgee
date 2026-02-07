# Environment Setup Guide

## 🎯 Purpose

This guide explains how to set up your environment for AegisForge, including environment variables, configuration files, and credential management.

---

## 📋 Prerequisites

- Python 3.8 or higher
- Git
- Text editor (VS Code, nano, vim, etc.)
- Basic command line knowledge

---

## 🚀 Quick Setup (Development)

### Step 1: Clone Repository
```bash
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
```

### Step 2: Create Environment File
```bash
# Copy the example environment file
cp .env.example .env
```

### Step 3: Review Default Values

The `.env.example` file contains default values suitable for local development:

```bash
# View the file
cat .env.example
```

**Default configuration includes:**
- SQLite database (no setup required)
- Development mode enabled
- Test credentials for educational demos
- CORS enabled for localhost
- Debug mode enabled

### Step 4: (Optional) Customize Values

Edit `.env` to customize:

```bash
nano .env
```

**Common customizations:**
```bash
# Change secret key (recommended)
FLASK_SECRET_KEY=your-unique-secret-key-here

# Change test passwords
TEST_USER_ALICE_PASSWORD=mycustompassword123
TEST_USER_BOB_PASSWORD=anothercustompass456

# Change log level
LOG_LEVEL=DEBUG  # or INFO, WARNING, ERROR
```

### Step 5: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 6: Initialize Database
```bash
python init_db.py
```

### Step 7: Run the Application
```bash
python aegisforge_api.py
```

---

## 🔧 Environment Variables Reference

### Core Flask Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | `development` | Flask environment mode |
| `FLASK_DEBUG` | `True` | Enable debug mode |
| `FLASK_SECRET_KEY` | (random) | Flask secret key |

### Database Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_TYPE` | `sqlite` | Database type |
| `DB_PATH` | `./aegisforge.db` | SQLite database path |
| `DATABASE_URL` | (auto) | Full database URL |

### Test Credentials (Educational Only)

| Variable | Default | Description |
|----------|---------|-------------|
| `TEST_USER_ALICE_PASSWORD` | `password123` | Alice's password |
| `TEST_USER_BOB_PASSWORD` | `securepass456` | Bob's password |
| `TEST_USER_ADMIN_PASSWORD` | `admin123` | Admin password |
| `TEST_USER_CAROL_PASSWORD` | `carol789` | Carol's password |

### Demo Credentials (A05 Misconfiguration)

| Variable | Default | Description |
|----------|---------|-------------|
| `DEMO_ADMIN_USERNAME` | `admin` | Default admin username |
| `DEMO_ADMIN_PASSWORD` | `admin` | Default admin password |
| `DEMO_ROOT_USERNAME` | `root` | Default root username |
| `DEMO_ROOT_PASSWORD` | `root` | Default root password |

### Security Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSION_COOKIE_SECURE` | `False` | Secure cookies (HTTPS only) |
| `SESSION_COOKIE_HTTPONLY` | `True` | HTTP-only cookies |
| `SESSION_COOKIE_SAMESITE` | `Lax` | SameSite cookie policy |
| `PERMANENT_SESSION_LIFETIME` | `3600` | Session lifetime (seconds) |

### CORS Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ORIGINS` | `localhost:*` | Allowed CORS origins |
| `CORS_ALLOW_CREDENTIALS` | `True` | Allow credentials in CORS |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_ENABLED` | `True` | Enable rate limiting |
| `RATE_LIMIT_DEFAULT` | `100 per hour` | Default rate limit |
| `RATE_LIMIT_STORAGE_URL` | `memory://` | Rate limit storage |

---

## 🔐 Generating Secure Values

### Secret Keys

**Python Method:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

**OpenSSL Method:**
```bash
openssl rand -hex 32
```

### Passwords

**Python Method:**
```python
import secrets
import string

alphabet = string.ascii_letters + string.digits + string.punctuation
password = ''.join(secrets.choice(alphabet) for _ in range(16))
print(password)
```

**OpenSSL Method:**
```bash
openssl rand -base64 16
```

---

## 📁 Configuration Files

### Root Level
- `.env` - Your environment variables (DO NOT commit!)
- `.env.example` - Template for environment variables
- `config.py` - Python configuration loader

### Backend Level
- `backend/.env.example` - Backend-specific template
- `backend/config.py` - Backend configuration

### SecureBank Level
- `backend/apps/securebank/.env.example` - SecureBank template
- `backend/apps/securebank/config.py` - SecureBank configuration

---

## ⚠️ Security Best Practices

### DO:
- ✅ Use `.env.example` as a template
- ✅ Generate unique secret keys
- ✅ Keep `.env` in `.gitignore`
- ✅ Use environment variables for all secrets
- ✅ Rotate secrets regularly in production

### DO NOT:
- ❌ Commit `.env` to version control
- ❌ Share `.env` files
- ❌ Use default values in production
- ❌ Hardcode secrets in code
- ❌ Reuse secrets across environments

---

## 🧪 Testing Your Setup

### Verify Environment Variables Loaded
```python
# test_config.py
from config import Config

config = Config()
print(f"Secret Key: {config.SECRET_KEY[:10]}...")
print(f"Database: {config.DB_PATH}")
print(f"Debug Mode: {config.DEBUG}")
```

Run:
```bash
python test_config.py
```

### Verify Database Connection
```bash
# Check if database file exists
ls -lh aegisforge.db

# Or for SecureBank
ls -lh backend/apps/securebank/securebank.db
```

---

## 🐛 Troubleshooting

### Issue: "Required environment variable not set"

**Solution:** Ensure you've created `.env` file:
```bash
cp .env.example .env
```

### Issue: Secret key too weak

**Solution:** Generate a strong secret key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Then add to `.env`:
```bash
FLASK_SECRET_KEY=<generated-value>
```

### Issue: Database not found

**Solution:** Initialize the database:
```bash
python init_db.py
```

---

## 📚 Next Steps

1. ✅ **Read:** [02_CREDENTIAL_MANAGEMENT.md](02_CREDENTIAL_MANAGEMENT.md)
2. ✅ **Review:** Test credentials in `CREDENTIALS.md`
3. ✅ **Explore:** Red vs Blue Team endpoints
4. ✅ **Learn:** Security vulnerabilities and fixes

---

**Last Updated:** February 2026
