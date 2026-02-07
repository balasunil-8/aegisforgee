# SecureBank Backend

Educational banking application backend for AegisForge demonstrating both vulnerable and secure implementations.

## Structure

```
backend/apps/securebank/
├── __init__.py                  # Package initialization
├── models.py                    # SQLAlchemy database models
├── database.py                  # Database initialization and connection
├── seed_data.py                 # Sample data seeding script
├── securebank_red_api.py        # Red Team (Vulnerable) API
├── securebank_blue_api.py       # Blue Team (Secure) API
└── README.md                    # This file
```

## Quick Start

### 1. Initialize Database

```bash
cd backend/apps/securebank
python database.py
```

### 2. Seed Sample Data

```bash
python seed_data.py
```

This creates:
- 4 test users (alice, bob, admin, carol)
- 6 bank accounts
- 10 sample transactions
- 6 beneficiaries
- User settings

### 3. Run Red Team (Vulnerable) API

```bash
python securebank_red_api.py
```

Runs on: `http://localhost:5000`

### 4. Run Blue Team (Secure) API

```bash
python securebank_blue_api.py
```

Runs on: `http://localhost:5001`

## Test Credentials

- **Username:** alice | **Password:** password123
- **Username:** bob | **Password:** securepass456
- **Username:** admin | **Password:** admin123
- **Username:** carol | **Password:** carol789

## Vulnerabilities (Red Team)

1. **SQL Injection** - Login endpoint
2. **IDOR** - Account access endpoint
3. **Race Condition** - Money transfer endpoint
4. **XSS** - Transaction notes
5. **Mass Assignment** - Profile update
6. **CSRF** - Settings update

## Security Features (Blue Team)

1. **Parameterized Queries** - Prevents SQL injection
2. **Authorization Checks** - Prevents IDOR
3. **Database Locking** - Prevents race conditions
4. **Output Encoding** - Prevents XSS
5. **Field Whitelisting** - Prevents mass assignment
6. **CSRF Tokens** - Prevents CSRF attacks

## API Endpoints

### Authentication
- `POST /api/{team}/securebank/login` - User login
- `POST /api/{team}/securebank/logout` - User logout
- `GET /api/{team}/securebank/session` - Get session info
- `GET /api/blue/securebank/csrf-token` - Get CSRF token (Blue only)

### Accounts
- `GET /api/{team}/securebank/accounts` - Get user's accounts
- `GET /api/{team}/securebank/account/<id>` - Get specific account

### Transactions
- `POST /api/{team}/securebank/transfer` - Transfer money
- `GET /api/{team}/securebank/transactions` - Get transactions
- `PUT /api/{team}/securebank/transaction/<id>/note` - Update note

### Profile
- `GET /api/{team}/securebank/profile` - Get user profile
- `PUT /api/{team}/securebank/profile` - Update profile

### Settings
- `GET /api/{team}/securebank/settings` - Get settings
- `POST /api/{team}/securebank/settings` - Update settings

### Beneficiaries
- `GET /api/{team}/securebank/beneficiaries` - Get beneficiaries
- `POST /api/{team}/securebank/beneficiaries` - Add beneficiary

### Dashboard
- `GET /api/{team}/securebank/dashboard` - Get dashboard data

Replace `{team}` with `red` or `blue`.

## Database Schema

### bank_users
- User accounts with authentication

### bank_accounts
- Bank accounts linked to users

### transactions
- Money transfer records

### beneficiaries
- Saved recipient accounts

### user_settings
- User preferences and settings

## Security Notes

⚠️ **Red Team API**: Contains intentional vulnerabilities for educational purposes. NEVER use in production.

✅ **Blue Team API**: Implements industry-standard security practices. Reference implementation for secure coding.
