# Test Credentials Documentation

## ⚠️ IMPORTANT NOTICE

**These credentials are for EDUCATIONAL TESTING ONLY.**

**DO NOT use these in production environments!**

---

## 🎓 Purpose

AegisForge is a security education platform with intentionally vulnerable "Red Team" endpoints. The credentials below are:

✅ Hardcoded for easy setup and learning
✅ Publicly documented (not secrets)
✅ Used in educational demonstrations
✅ Designed to show insecure practices

**For production, use environment variables (see `.env.example`)**

---

## 🔐 SecureBank Test Users

### Alice (Regular User)
- **Username:** `alice`
- **Password:** `password123`
- **Email:** alice@example.com
- **Accounts:** 
  - Checking: 1234567890 ($50,000.00)
  - Savings: 1234567891 ($125,000.50)

### Bob (Regular User)
- **Username:** `bob`
- **Password:** `securepass456`
- **Email:** bob@example.com
- **Accounts:**
  - Checking: 2345678901 ($15,000.25)
  - Savings: 2345678902 ($75,000.00)

### Admin (Administrator)
- **Username:** `admin`
- **Password:** `admin123`
- **Email:** admin@aegisbank.com
- **Role:** Administrator

### Carol (Regular User)
- **Username:** `carol`
- **Password:** `carol789`
- **Email:** carol@example.com
- **Accounts:**
  - Checking: 9876543210 ($30,000.00)
  - Savings: 9876543211 ($90,000.00)

---

## 🚨 OWASP A05 Default Credentials (Misconfiguration Demo)

### Default Admin Accounts (Intentionally Weak)
- **admin/admin** - Administrator role
- **root/root** - Administrator role
- **test/test123** - User role
- **guest/guest** - Guest role

**Location:** `backend/owasp/web_2021/a05_misconfiguration_red.py`

**Purpose:** Demonstrate security misconfiguration vulnerability

---

## 🔵 Blue Team Secure Credentials

### Secure Admin (Hashed Password)
- **Username:** `admin`
- **Password:** `Admin123!@#`
- **Hash:** SHA-256 hashed
- **Location:** `backend/owasp/web_2021/a05_misconfiguration_blue.py`

### Secure User
- **Username:** `john_doe`
- **Password:** `JD$ecure2024`
- **Hash:** SHA-256 hashed

**Note:** Blue Team endpoints demonstrate proper password hashing

---

## 🔑 Secret Keys

### Red Team (Insecure)
```python
# backend/apps/securebank/securebank_red_api.py
app.secret_key = 'insecure-secret-key-123'
```

**Purpose:** Demonstrate weak secret key vulnerability

### Blue Team (Secure)
```python
# backend/apps/securebank/securebank_blue_api.py
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
```

**Purpose:** Demonstrate proper secret key management

---

## 🛠️ Using Environment Variables

### For Development
1. Copy `.env.example` to `.env`
2. Fill in your custom values
3. Never commit `.env` to version control

### For Production
1. Generate strong random passwords:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
2. Set environment variables in your deployment platform
3. Use only Blue Team endpoints
4. Disable Red Team endpoints

---

## 📖 SQL Injection Demo Credentials

### Bypass Login (Red Team Endpoint)
**Endpoint:** `/api/red/securebank/login`

**Username:** `admin' OR '1'='1'--`
**Password:** `anything`

**Result:** Bypass authentication via SQL injection

**Purpose:** Educational demonstration of SQL injection vulnerability

---

## ⚖️ Legal Notice

These credentials are provided for authorized educational and testing purposes only. Unauthorized access to systems using these credentials may be illegal.

**Use responsibly and only in controlled lab environments!**

---

## 📚 Related Documentation

- `SECURITY.md` - Security policy
- `.env.example` - Environment variable template
- `docs/security/02_CREDENTIAL_MANAGEMENT.md` - Detailed guide

---

**Last Updated:** February 2026
