# 🏗️ SecureBank Architecture Guide

**Complete Technical Architecture and Design Documentation**

Part of the AegisForge Security Education Platform

---

## 📋 Table of Contents

1. [Introduction](#introduction)
2. [High-Level Architecture](#high-level-architecture)
3. [Technology Stack](#technology-stack)
4. [Database Design](#database-design)
5. [Backend Architecture](#backend-architecture)
6. [Frontend Architecture](#frontend-architecture)
7. [API Design](#api-design)
8. [Security Architecture](#security-architecture)
9. [Data Flow Diagrams](#data-flow-diagrams)
10. [Component Interaction](#component-interaction)
11. [Design Patterns](#design-patterns)
12. [File Structure](#file-structure)
13. [Configuration Management](#configuration-management)
14. [Deployment Architecture](#deployment-architecture)
15. [Performance Considerations](#performance-considerations)

---

## Introduction

This guide explains the technical architecture of SecureBank - how all the pieces fit together to create a functioning banking application.

### What is Architecture?

**Architecture** is the blueprint of a software system. Just like building a house needs:
- Foundation (database)
- Frame (backend structure)
- Walls (APIs)
- Exterior (frontend/UI)
- Electrical/plumbing (security, authentication)

Software needs a solid structure too!

### Why Two Versions?

SecureBank has **dual-mode architecture**:

**Red Team (Vulnerable):**
- Demonstrates common security mistakes
- Educational tool for learning attacks
- Shows what NOT to do

**Blue Team (Secure):**
- Industry-standard security practices
- Educational tool for learning defenses
- Shows the RIGHT way to build applications

**Same architecture, different implementations** - making it perfect for comparison learning.

### Who Should Read This?

- **Developers** wanting to understand banking application design
- **Security professionals** learning application architecture
- **Students** studying software engineering
- **Anyone** curious about how web applications work internally

### Architecture Goals

SecureBank's architecture prioritizes:

1. **Educational Value**: Clear, understandable code structure
2. **Realistic Design**: Mirrors real banking applications
3. **Comparison Learning**: Easy to compare Red vs Blue implementations
4. **Modularity**: Separate concerns (database, API, UI)
5. **Scalability**: Can be extended with new features
6. **Testability**: Easy to test individual components

---

## High-Level Architecture

SecureBank follows a **three-tier architecture** pattern:

```
┌─────────────────────────────────────────────────────┐
│                 PRESENTATION TIER                   │
│              (Frontend - HTML/CSS/JS)               │
│                                                     │
│  ┌──────────────┐           ┌──────────────┐      │
│  │  Red Team    │           │  Blue Team   │      │
│  │  Frontend    │           │  Frontend    │      │
│  │  Port 8000   │           │  Port 8001   │      │
│  └──────────────┘           └──────────────┘      │
└─────────────────────────────────────────────────────┘
                       │
                       │ HTTP/HTTPS Requests
                       │ (REST API Calls)
                       ↓
┌─────────────────────────────────────────────────────┐
│                  APPLICATION TIER                   │
│               (Backend - Python/Flask)              │
│                                                     │
│  ┌──────────────┐           ┌──────────────┐      │
│  │  Red Team    │           │  Blue Team   │      │
│  │     API      │           │     API      │      │
│  │  Port 5001   │           │  Port 5002   │      │
│  └──────────────┘           └──────────────┘      │
└─────────────────────────────────────────────────────┘
                       │
                       │ SQL Queries
                       │ (SQLAlchemy ORM)
                       ↓
┌─────────────────────────────────────────────────────┐
│                    DATA TIER                        │
│                (Database - SQLite)                  │
│                                                     │
│              ┌──────────────────┐                  │
│              │  securebank.db   │                  │
│              │  - bank_users    │                  │
│              │  - bank_accounts │                  │
│              │  - transactions  │                  │
│              │  - beneficiaries │                  │
│              │  - user_settings │                  │
│              └──────────────────┘                  │
└─────────────────────────────────────────────────────┘
```

### Why Three Tiers?

**Separation of Concerns** - Each tier has a specific job:

**Tier 1: Presentation (Frontend)**
- **Job**: User interface and user experience
- **Responsibilities**: 
  - Display data beautifully
  - Capture user input
  - Communicate with API
  - Client-side validation
- **Technology**: HTML, CSS, JavaScript
- **Why separate?**: UI changes shouldn't break backend logic

**Tier 2: Application (Backend API)**
- **Job**: Business logic and processing
- **Responsibilities**:
  - Validate requests
  - Process transactions
  - Enforce business rules
  - Manage authentication/authorization
  - Database operations
- **Technology**: Python, Flask framework
- **Why separate?**: Can be used by multiple frontends (web, mobile app, etc.)

**Tier 3: Data (Database)**
- **Job**: Store and retrieve data
- **Responsibilities**:
  - Persist information
  - Ensure data integrity
  - Handle concurrent access
  - Provide fast queries
- **Technology**: SQLite (or PostgreSQL/MySQL for production)
- **Why separate?**: Can switch database systems without changing application code

### Request Flow Example

**User clicks "Transfer Money":**

```
1. Frontend (JavaScript)
   ↓ User clicks "Confirm Transfer"
   
2. Frontend validates input
   ↓ Amount > 0? Account selected? ✓
   
3. Frontend sends HTTP POST request
   ↓ POST /api/transfer
   ↓ Body: { from_account: 1, to_account: 2, amount: 500 }
   
4. Backend receives request
   ↓ Flask route: @app.route('/api/transfer')
   
5. Backend validates authorization
   ↓ Is user logged in? ✓
   ↓ Does user own from_account? ✓
   
6. Backend queries database
   ↓ SQLAlchemy: Account.query.get(1)
   ↓ Check balance >= 500? ✓
   
7. Backend processes transfer
   ↓ Deduct 500 from Account 1
   ↓ Add 500 to Account 2
   ↓ Create transaction record
   
8. Backend commits to database
   ↓ SQLAlchemy: db.session.commit()
   
9. Backend sends response
   ↓ JSON: { success: true, transaction_id: 123 }
   
10. Frontend displays confirmation
    ↓ "Transfer successful!"
    ↓ Update displayed balances
```

---

## Technology Stack

SecureBank uses modern, industry-standard technologies.

### Backend Stack

**Language: Python 3.8+**
- **Why Python?** 
  - Easy to learn and read
  - Huge ecosystem of libraries
  - Great for rapid development
  - Industry standard for web apps
  - Excellent security libraries

**Web Framework: Flask 2.3+**
```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/health')
def health_check():
    return jsonify({'status': 'healthy'})
```

- **Why Flask?**
  - Lightweight and flexible
  - Simple routing system
  - Great for REST APIs
  - Extensive documentation
  - Large community

**ORM: SQLAlchemy 2.0+**
```python
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class BankUser(Base):
    __tablename__ = 'bank_users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
```

- **Why SQLAlchemy?**
  - Object-Relational Mapping (write Python, not SQL)
  - Database-agnostic (switch DB easily)
  - Prevents SQL injection when used correctly
  - Powerful query API
  - Built-in relationship management

**Security Libraries:**

**bcrypt - Password hashing**
```python
import bcrypt

# Hash password
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Verify password
if bcrypt.checkpw(password.encode(), stored_hash):
    # Password correct
```

**Flask-CORS - Cross-Origin Resource Sharing**
```python
from flask_cors import CORS

CORS(app, origins=['http://127.0.0.1:8000'])
```

**Database: SQLite 3**
- **Why SQLite?**
  - No server setup required
  - Self-contained (single file)
  - Perfect for learning/testing
  - Supports SQL features needed
  - Built into Python

**Production alternative: PostgreSQL**
- More scalable
- Better concurrency handling
- Advanced features (JSON columns, full-text search)

### Frontend Stack

**HTML5**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureBank - Modern Banking</title>
</head>
<body>
    <!-- Semantic HTML -->
    <header>...</header>
    <main>...</main>
    <footer>...</footer>
</body>
</html>
```

**CSS3**
```css
/* Modern CSS with Flexbox and Grid */
.account-card {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    padding: 1.5rem;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}
```

**Vanilla JavaScript (ES6+)**
```javascript
// Modern JavaScript features
const fetchAccounts = async () => {
    try {
        const response = await fetch(`${API_URL}/accounts`, {
            headers: {
                'Authorization': `Bearer ${getToken()}`
            }
        });
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Failed to fetch accounts:', error);
    }
};
```

**Why no framework (React/Vue/Angular)?**
- Keeps focus on security concepts, not framework complexity
- Easier to understand for beginners
- Shows how web apps work fundamentally
- Smaller codebase
- Faster page loads

**CSS Framework: Custom (Banking-themed)**
- Professional banking aesthetics
- Responsive design
- Accessibility (WCAG 2.1 AA)
- Dark mode support (Blue Team)

### Development Tools

**Version Control: Git**
```bash
git clone https://github.com/yourusername/aegisforgee.git
```

**Package Management: pip**
```bash
pip install -r requirements.txt
```

**Testing Tools:**
- Postman (API testing)
- Burp Suite (Security testing)
- SQLMap (SQL injection testing)
- OWASP ZAP (Vulnerability scanning)

---

## Database Design

SecureBank uses a **relational database** with normalized tables and proper relationships.

### Entity-Relationship Diagram

```
┌─────────────────┐
│   bank_users    │
├─────────────────┤
│ id (PK)         │
│ username        │────┐
│ password        │    │
│ email           │    │
│ full_name       │    │
│ phone           │    │ One user has
│ address         │    │ many accounts
│ role            │    │
│ is_active       │    │
│ created_at      │    │
│ last_login      │    │
└─────────────────┘    │
                       │
                       ↓
              ┌─────────────────┐
              │  bank_accounts  │
              ├─────────────────┤
              │ id (PK)         │
              │ user_id (FK)    │◄───────┐
              │ account_number  │        │
              │ account_type    │        │ One account has
              │ balance         │        │ many transactions
              │ currency        │        │
              │ status          │        │
              │ opened_date     │        │
              └─────────────────┘        │
                                         │
              ┌─────────────────┐        │
              │  transactions   │        │
              ├─────────────────┤        │
              │ id (PK)         │        │
              │ from_account_id │────────┘
              │ to_account_id   │────────┐
              │ amount          │        │
              │ transaction_type│        │
              │ description     │        │
              │ note            │        │
              │ timestamp       │        │
              │ status          │        │
              └─────────────────┘        │
                                         │
┌─────────────────┐                     │
│  beneficiaries  │                     │
├─────────────────┤                     │
│ id (PK)         │                     │
│ user_id (FK)    │─────────────────────┘
│ name            │
│ account_number  │
│ bank_name       │
│ nickname        │
│ created_at      │
└─────────────────┘

┌─────────────────┐
│  user_settings  │
├─────────────────┤
│ id (PK)         │
│ user_id (FK)    │─────┐
│ email_alerts    │     │ One user has
│ sms_alerts      │     │ one settings
│ language        │     │ record
│ timezone        │     │
│ currency_format │     │
│ theme           │     │
└─────────────────┘     │
                        │
            ┌───────────┘
            │
       (back to bank_users)
```

### Table Schemas

#### bank_users Table

**Purpose:** Store user account information and credentials.

```sql
CREATE TABLE bank_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,  -- bcrypt hash in Blue Team
    email VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    phone VARCHAR(20),
    address TEXT,
    role VARCHAR(20) DEFAULT 'user',  -- 'user' or 'admin'
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
);

-- Indexes for performance
CREATE INDEX idx_username ON bank_users(username);
CREATE INDEX idx_email ON bank_users(email);
```

**Why these fields?**

- **id**: Unique identifier (primary key)
- **username**: Login identifier, must be unique
- **password**: Hashed password (NEVER plain text in production)
- **email**: Contact and recovery
- **full_name**: Display name
- **phone**: Two-factor authentication, alerts
- **address**: Mailing address for statements
- **role**: Access control (user vs admin)
- **is_active**: Soft delete (deactivate without deleting)
- **created_at**: Account age tracking
- **last_login**: Security monitoring

**Sample Data:**
```sql
INSERT INTO bank_users (username, password, email, full_name, role) VALUES
('john.doe', 'hashed_password_here', 'john.doe@email.com', 'John Doe', 'user');
```

#### bank_accounts Table

**Purpose:** Store banking accounts (checking, savings, credit).

```sql
CREATE TABLE bank_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    account_number VARCHAR(20) UNIQUE NOT NULL,
    account_type VARCHAR(20) NOT NULL,  -- 'Checking', 'Savings', 'Credit'
    balance FLOAT DEFAULT 0.0 NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    status VARCHAR(20) DEFAULT 'active',  -- 'active', 'frozen', 'closed'
    opened_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES bank_users(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX idx_account_user ON bank_accounts(user_id);
CREATE INDEX idx_account_number ON bank_accounts(account_number);
CREATE INDEX idx_account_status ON bank_accounts(status);
```

**Why these fields?**

- **id**: Unique identifier
- **user_id**: Links to bank_users (foreign key)
- **account_number**: Human-readable account identifier
- **account_type**: Determines account behavior
- **balance**: Current amount (FLOAT for currency)
- **currency**: Multi-currency support
- **status**: Account state management
- **opened_date**: Account creation tracking

**Account Number Format:**
```
CHK-1001  → Checking account
SAV-1002  → Savings account
CRD-1003  → Credit account
```

**Sample Data:**
```sql
INSERT INTO bank_accounts (user_id, account_number, account_type, balance) VALUES
(1, 'CHK-1001', 'Checking', 5000.00),
(1, 'SAV-1002', 'Savings', 10000.00);
```

#### transactions Table

**Purpose:** Record all financial transactions.

```sql
CREATE TABLE transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_account_id INTEGER,
    to_account_id INTEGER,
    amount FLOAT NOT NULL,
    transaction_type VARCHAR(20) NOT NULL,  -- 'transfer', 'deposit', 'withdrawal'
    description VARCHAR(200),
    note TEXT,  -- User-provided note (XSS vulnerability demo)
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'completed',  -- 'pending', 'completed', 'failed'
    
    FOREIGN KEY (from_account_id) REFERENCES bank_accounts(id),
    FOREIGN KEY (to_account_id) REFERENCES bank_accounts(id)
);

-- Indexes for fast queries
CREATE INDEX idx_transaction_from ON transactions(from_account_id);
CREATE INDEX idx_transaction_to ON transactions(to_account_id);
CREATE INDEX idx_transaction_timestamp ON transactions(timestamp DESC);
CREATE INDEX idx_transaction_type ON transactions(transaction_type);
```

**Why these fields?**

- **id**: Unique transaction identifier
- **from_account_id**: Source account (null for deposits)
- **to_account_id**: Destination account (null for withdrawals)
- **amount**: Transaction value (always positive)
- **transaction_type**: Categorization
- **description**: Auto-generated description
- **note**: User-provided context
- **timestamp**: When transaction occurred
- **status**: Transaction state

**Sample Data:**
```sql
INSERT INTO transactions (from_account_id, to_account_id, amount, transaction_type, description) VALUES
(1, 2, 500.00, 'transfer', 'Transfer from Checking to Savings');
```

#### beneficiaries Table

**Purpose:** Store saved transfer recipients.

```sql
CREATE TABLE beneficiaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name VARCHAR(100) NOT NULL,
    account_number VARCHAR(20) NOT NULL,
    bank_name VARCHAR(100) DEFAULT 'SecureBank',
    nickname VARCHAR(50),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES bank_users(id) ON DELETE CASCADE
);

CREATE INDEX idx_beneficiary_user ON beneficiaries(user_id);
```

**Sample Data:**
```sql
INSERT INTO beneficiaries (user_id, name, account_number, nickname) VALUES
(1, 'Jane Smith', 'SAV-2001', 'Sister');
```

#### user_settings Table

**Purpose:** Store user preferences and configuration.

```sql
CREATE TABLE user_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    email_alerts BOOLEAN DEFAULT 1,
    sms_alerts BOOLEAN DEFAULT 0,
    monthly_statements BOOLEAN DEFAULT 1,
    marketing_emails BOOLEAN DEFAULT 0,
    language VARCHAR(10) DEFAULT 'en',
    timezone VARCHAR(50) DEFAULT 'UTC',
    currency_format VARCHAR(10) DEFAULT 'USD',
    date_format VARCHAR(20) DEFAULT 'MM/DD/YYYY',
    theme VARCHAR(20) DEFAULT 'light',
    
    FOREIGN KEY (user_id) REFERENCES bank_users(id) ON DELETE CASCADE
);
```

### Database Relationships

**One-to-Many:**
- One user → Many accounts
- One user → Many beneficiaries
- One account → Many transactions (as source)
- One account → Many transactions (as destination)

**One-to-One:**
- One user → One settings record

**Many-to-Many (through transactions):**
- Accounts can transact with many other accounts
- Transactions table acts as junction table

### Database Normalization

SecureBank follows **Third Normal Form (3NF)**:

**1NF (First Normal Form):**
- ✅ All columns contain atomic values (no arrays)
- ✅ Each column contains values of a single type
- ✅ Each column has a unique name
- ✅ Order doesn't matter

**2NF (Second Normal Form):**
- ✅ Meets 1NF requirements
- ✅ No partial dependencies (all non-key attributes depend on entire primary key)

**3NF (Third Normal Form):**
- ✅ Meets 2NF requirements
- ✅ No transitive dependencies (non-key attributes don't depend on other non-key attributes)

**Example of proper normalization:**

**Bad (denormalized):**
```sql
-- User info repeated for each transaction
transactions (
    id, user_name, user_email, from_account, to_account, amount
)
```

**Good (normalized):**
```sql
-- User info stored once, referenced by ID
users (id, name, email)
accounts (id, user_id, account_number)
transactions (id, from_account_id, to_account_id, amount)
```

### Database Constraints

**Primary Keys:**
- Ensure uniqueness
- Auto-increment for simplicity

**Foreign Keys:**
- Maintain referential integrity
- CASCADE delete: Deleting user deletes their accounts
- RESTRICT: Can't delete account with existing transactions

**Unique Constraints:**
- username (no duplicate usernames)
- email (one email per user)
- account_number (unique identifiers)

**Not Null Constraints:**
- Critical fields must have values
- Prevents incomplete data

**Default Values:**
- Sensible defaults (status='active', currency='USD')
- Reduces application logic

---

## Backend Architecture

The backend is built with **Flask** and follows **MVC pattern** (Model-View-Controller).

### MVC Pattern

```
┌─────────────────────────────────────────┐
│              Controller                 │
│       (Flask Routes/Endpoints)          │
│                                         │
│  @app.route('/api/accounts')            │
│  def get_accounts():                    │
│      # 1. Receive request               │
│      # 2. Call model methods            │
│      # 3. Return view (JSON)            │
└─────────────────────────────────────────┘
           │                  ▲
           │ Calls            │ Returns
           │ Model            │ Data
           ↓                  │
┌─────────────────┐  ┌────────────────┐
│     Model       │  │      View      │
│  (Data/Logic)   │  │  (JSON/HTML)   │
│                 │  │                │
│  class Account: │  │  jsonify({     │
│    balance      │  │    'balance':  │
│    transfer()   │  │     5000       │
│                 │  │  })            │
└─────────────────┘  └────────────────┘
```

### File Structure

```
backend/apps/securebank/
├── __init__.py                    # Package initializer
├── models.py                      # Database models (M)
├── database.py                    # Database setup
├── seed_data.py                   # Sample data
├── securebank_red_api.py          # Red Team controller (C)
├── securebank_blue_api.py         # Blue Team controller (C)
└── utils/
    ├── auth.py                    # Authentication helpers
    ├── validators.py              # Input validation
    └── security.py                # Security utilities
```

### Models (models.py)

Models represent database tables as Python classes.

```python
from sqlalchemy import Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class BankUser(Base):
    """User model representing bank customers"""
    __tablename__ = 'bank_users'
    
    # Columns
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    role = Column(String(20), default='user')
    
    # Relationships (ORM magic!)
    accounts = relationship('BankAccount', back_populates='user')
    
    def to_dict(self):
        """Convert model to dictionary for JSON response"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role
        }
    
    def check_password(self, password):
        """Verify password (Blue Team uses bcrypt)"""
        # Red Team: Plain text comparison
        return self.password == password
        
        # Blue Team: Bcrypt comparison
        # return bcrypt.checkpw(password.encode(), self.password)
```

**Why ORM?**
- Write Python instead of SQL
- Database-agnostic (switch from SQLite to PostgreSQL easily)
- Prevents SQL injection (when used correctly)
- Automatic relationship handling

### Controllers (APIs)

Controllers handle HTTP requests and orchestrate business logic.

**Red Team API Structure:**

```python
from flask import Flask, request, jsonify
from flask_cors import CORS
from models import BankUser, BankAccount, Transaction
from database import session

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests

# ============================================
# Authentication Endpoints
# ============================================

@app.route('/api/login', methods=['POST'])
def login():
    """
    User login - VULNERABLE to SQL Injection
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # VULNERABLE: String concatenation in SQL
    query = f"SELECT * FROM bank_users WHERE username='{username}' AND password='{password}'"
    # SQL Injection possible: username = "admin' OR '1'='1"
    
    user = session.execute(query).first()
    if user:
        return jsonify({
            'success': True,
            'token': generate_token(user.id),
            'user': user.to_dict()
        })
    return jsonify({'error': 'Invalid credentials'}), 401

# ============================================
# Account Endpoints
# ============================================

@app.route('/api/accounts/<int:account_id>')
def get_account(account_id):
    """
    Get account details - VULNERABLE to IDOR
    """
    # NO AUTHORIZATION CHECK!
    account = BankAccount.query.get(account_id)
    if account:
        return jsonify(account.to_dict())
    return jsonify({'error': 'Account not found'}), 404

# ============================================
# Transaction Endpoints
# ============================================

@app.route('/api/transfer', methods=['POST'])
def transfer():
    """
    Transfer money - VULNERABLE to Race Condition
    """
    data = request.get_json()
    from_id = data['from_account']
    to_id = data['to_account']
    amount = float(data['amount'])
    
    # NO LOCKING - Race condition possible
    from_account = BankAccount.query.get(from_id)
    to_account = BankAccount.query.get(to_id)
    
    if from_account.balance >= amount:
        from_account.balance -= amount
        to_account.balance += amount
        session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Insufficient funds'}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
```

**Blue Team API Structure:**

```python
from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
from functools import wraps
from models import BankUser, BankAccount, Transaction
from database import session

app = Flask(__name__)
CORS(app, origins=['http://127.0.0.1:8001'])  # Strict CORS

# ============================================
# Decorators for Security
# ============================================

def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not validate_token(token):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(max_requests=5, window=60):
    """Decorator to rate limit requests"""
    # Implementation...

# ============================================
# Authentication Endpoints
# ============================================

@app.route('/api/login', methods=['POST'])
@rate_limit(max_requests=5, window=300)  # 5 attempts per 5 minutes
def login():
    """
    User login - SECURE with parameterized query
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # SECURE: Parameterized query prevents SQL injection
    user = BankUser.query.filter_by(username=username).first()
    
    if user and bcrypt.checkpw(password.encode(), user.password):
        return jsonify({
            'success': True,
            'token': generate_secure_token(user.id),
            'user': user.to_dict()
        })
    
    # Don't reveal whether username or password was wrong
    return jsonify({'error': 'Invalid credentials'}), 401

# ============================================
# Account Endpoints
# ============================================

@app.route('/api/accounts/<int:account_id>')
@login_required
def get_account(account_id):
    """
    Get account details - SECURE with authorization
    """
    current_user_id = get_user_from_token(request.headers.get('Authorization'))
    account = BankAccount.query.get(account_id)
    
    if not account:
        return jsonify({'error': 'Account not found'}), 404
    
    # AUTHORIZATION CHECK
    if account.user_id != current_user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify(account.to_dict())

# ============================================
# Transaction Endpoints
# ============================================

@app.route('/api/transfer', methods=['POST'])
@login_required
@csrf_protected  # CSRF token validation
def transfer():
    """
    Transfer money - SECURE with locking
    """
    data = request.get_json()
    from_id = data['from_account']
    to_id = data['to_account']
    amount = float(data['amount'])
    
    # WITH LOCKING - Prevents race conditions
    with session.begin_nested():
        from_account = BankAccount.query.with_for_update().get(from_id)
        to_account = BankAccount.query.with_for_update().get(to_id)
        
        # Authorization check
        current_user_id = get_user_from_token(request.headers.get('Authorization'))
        if from_account.user_id != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        if from_account.balance >= amount:
            from_account.balance -= amount
            to_account.balance += amount
            
            # Create transaction record
            transaction = Transaction(
                from_account_id=from_id,
                to_account_id=to_id,
                amount=amount,
                transaction_type='transfer'
            )
            session.add(transaction)
            session.commit()
            
            return jsonify({
                'success': True,
                'transaction_id': transaction.id
            })
        
        return jsonify({'error': 'Insufficient funds'}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)  # Debug OFF
```

### Key Differences: Red vs Blue Backend

| Feature | Red Team | Blue Team |
|---------|----------|-----------|
| **SQL Queries** | String concatenation | Parameterized/ORM |
| **Authorization** | Missing checks | Comprehensive validation |
| **Password Storage** | Plain text | bcrypt hashed |
| **Session Management** | Weak tokens | Secure JWT tokens |
| **Rate Limiting** | None | Implemented |
| **CSRF Protection** | None | Token validation |
| **Logging** | Minimal | Comprehensive |
| **Error Messages** | Detailed (info leak) | Generic |
| **Database Locking** | None | Row-level locks |
| **Input Validation** | Client-side only | Server-side strict |

---

## Frontend Architecture

The frontend is built with **vanilla JavaScript** and follows **component-based architecture**.

### File Structure

```
frontend/apps/securebank/
├── red/                          # Red Team (vulnerable)
│   ├── login.html
│   ├── dashboard.html
│   ├── accounts.html
│   ├── transfer.html
│   ├── transactions.html
│   ├── profile.html
│   ├── settings.html
│   ├── css/
│   │   ├── banking.css           # Main styles
│   │   ├── responsive.css        # Mobile/tablet
│   │   └── components.css        # Reusable components
│   └── js/
│       ├── config.js             # API configuration
│       ├── utils.js              # Helper functions
│       ├── auth.js               # Authentication
│       ├── api.js                # API calls
│       ├── dashboard.js          # Dashboard logic
│       ├── accounts.js           # Accounts logic
│       ├── transfer.js           # Transfer logic
│       └── transactions.js       # Transaction logic
│
└── blue/                         # Blue Team (secure)
    └── [Same structure with security fixes]
```

### Component Architecture

**Modular JavaScript:**

```javascript
// config.js - Configuration
const CONFIG = {
    API_BASE_URL: 'http://127.0.0.1:5001/api',
    TIMEOUT: 5000,
    DEBUG: true
};

// auth.js - Authentication module
const Auth = {
    login: async (username, password) => {
        const response = await fetch(`${CONFIG.API_BASE_URL}/login`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        const data = await response.json();
        if (data.success) {
            localStorage.setItem('authToken', data.token);
            localStorage.setItem('userId', data.user.id);
            return true;
        }
        return false;
    },
    
    logout: () => {
        localStorage.removeItem('authToken');
        localStorage.removeItem('userId');
        window.location.href = 'login.html';
    },
    
    isAuthenticated: () => {
        return localStorage.getItem('authToken') !== null;
    },
    
    getToken: () => {
        return localStorage.getItem('authToken');
    }
};

// api.js - API communication module
const API = {
    call: async (endpoint, options = {}) => {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${Auth.getToken()}`
            }
        };
        
        const response = await fetch(
            `${CONFIG.API_BASE_URL}${endpoint}`,
            {...defaultOptions, ...options}
        );
        
        if (response.status === 401) {
            Auth.logout();
            return;
        }
        
        return await response.json();
    },
    
    getAccounts: () => API.call('/accounts'),
    getTransactions: () => API.call('/transactions'),
    transfer: (data) => API.call('/transfer', {
        method: 'POST',
        body: JSON.stringify(data)
    })
};

// dashboard.js - Dashboard page logic
document.addEventListener('DOMContentLoaded', async () => {
    if (!Auth.isAuthenticated()) {
        window.location.href = 'login.html';
        return;
    }
    
    try {
        const accounts = await API.getAccounts();
        renderAccounts(accounts);
        
        const transactions = await API.getTransactions();
        renderRecentTransactions(transactions.slice(0, 5));
        
        updateTotalBalance(accounts);
    } catch (error) {
        console.error('Failed to load dashboard:', error);
        showError('Failed to load dashboard data');
    }
});

function renderAccounts(accounts) {
    const container = document.getElementById('accounts-container');
    container.innerHTML = accounts.map(account => `
        <div class="account-card">
            <h3>${account.account_type} Account</h3>
            <p class="account-number">${account.account_number}</p>
            <p class="balance">$${account.balance.toFixed(2)}</p>
            <button onclick="viewAccount(${account.id})">View Details</button>
        </div>
    `).join('');
}
```

### State Management

**Simple state management with localStorage:**

```javascript
const State = {
    // Get state
    get: (key) => {
        const value = localStorage.getItem(key);
        try {
            return JSON.parse(value);
        } catch {
            return value;
        }
    },
    
    // Set state
    set: (key, value) => {
        const serialized = typeof value === 'object' 
            ? JSON.stringify(value) 
            : value;
        localStorage.setItem(key, serialized);
    },
    
    // Remove state
    remove: (key) => {
        localStorage.removeItem(key);
    },
    
    // Clear all state
    clear: () => {
        localStorage.clear();
    }
};

// Usage
State.set('user', {id: 1, username: 'john.doe'});
const user = State.get('user');
```

### CSS Architecture

**BEM (Block Element Modifier) naming convention:**

```css
/* Block */
.account-card {
    padding: 1.5rem;
    border-radius: 8px;
    background: white;
}

/* Element */
.account-card__header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 1rem;
}

.account-card__balance {
    font-size: 2rem;
    font-weight: bold;
    color: #2C5F8D;
}

/* Modifier */
.account-card--checking {
    border-left: 4px solid #2C5F8D;
}

.account-card--savings {
    border-left: 4px solid #28A745;
}

.account-card--credit {
    border-left: 4px solid #DC3545;
}
```

**Responsive design:**

```css
/* Mobile first approach */
.account-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 1rem;
}

/* Tablet */
@media (min-width: 768px) {
    .account-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

/* Desktop */
@media (min-width: 1024px) {
    .account-grid {
        grid-template-columns: repeat(3, 1fr);
    }
}
```

---

## API Design

SecureBank follows **RESTful API** principles.

### REST Principles

**1. Resource-Based URLs**
```
/api/accounts          ← Collection
/api/accounts/1        ← Specific resource
/api/transactions      ← Collection
```

**2. HTTP Methods for CRUD**
- GET: Read data
- POST: Create new resource
- PUT: Update existing resource
- DELETE: Remove resource

**3. Stateless**
- Each request contains all necessary information
- No server-side session storage (token-based auth)

**4. JSON Responses**
```json
{
  "success": true,
  "data": {...},
  "message": "Operation successful"
}
```

### Complete API Reference

#### Authentication

**POST /api/login**
```json
// Request
{
  "username": "john.doe",
  "password": "password123"
}

// Response
{
  "success": true,
  "token": "eyJhbGc...",
  "user": {
    "id": 1,
    "username": "john.doe",
    "full_name": "John Doe",
    "role": "user"
  }
}
```

**POST /api/logout**
```json
// Request
Headers: {
  "Authorization": "Bearer eyJhbGc..."
}

// Response
{
  "success": true,
  "message": "Logged out successfully"
}
```

#### Accounts

**GET /api/accounts**
```json
// Response
[
  {
    "id": 1,
    "account_number": "CHK-1001",
    "account_type": "Checking",
    "balance": 5000.00,
    "currency": "USD",
    "status": "active"
  },
  {
    "id": 2,
    "account_number": "SAV-1002",
    "account_type": "Savings",
    "balance": 10000.00,
    "currency": "USD",
    "status": "active"
  }
]
```

**GET /api/accounts/:id**
```json
// Response
{
  "id": 1,
  "account_number": "CHK-1001",
  "account_type": "Checking",
  "balance": 5000.00,
  "currency": "USD",
  "status": "active",
  "opened_date": "2023-01-01T00:00:00"
}
```

#### Transactions

**GET /api/transactions**
```json
// Response
[
  {
    "id": 1,
    "from_account": "CHK-1001",
    "to_account": "SAV-1002",
    "amount": 500.00,
    "transaction_type": "transfer",
    "description": "Transfer to Savings",
    "note": "Monthly savings",
    "timestamp": "2024-01-15T10:30:00",
    "status": "completed"
  }
]
```

**POST /api/transfer**
```json
// Request
{
  "from_account": 1,
  "to_account": 2,
  "amount": 500.00,
  "note": "Monthly savings"
}

// Response
{
  "success": true,
  "transaction_id": 123,
  "new_balance": 4500.00
}
```

#### Profile

**GET /api/profile**
```json
// Response
{
  "id": 1,
  "username": "john.doe",
  "email": "john.doe@email.com",
  "full_name": "John Doe",
  "phone": "(555) 123-4567",
  "address": "123 Main St, Anytown, ST 12345",
  "role": "user",
  "created_at": "2023-01-01T00:00:00"
}
```

**PUT /api/profile**
```json
// Request
{
  "full_name": "John Doe Jr.",
  "email": "john.doe.jr@email.com",
  "phone": "(555) 987-6543"
}

// Response
{
  "success": true,
  "message": "Profile updated successfully"
}
```

### Error Handling

**Consistent error responses:**

```json
// 400 Bad Request
{
  "error": "Invalid input",
  "details": {
    "amount": "Must be greater than 0"
  }
}

// 401 Unauthorized
{
  "error": "Authentication required",
  "code": "AUTH_REQUIRED"
}

// 403 Forbidden
{
  "error": "Unauthorized access",
  "code": "ACCESS_DENIED"
}

// 404 Not Found
{
  "error": "Resource not found",
  "code": "NOT_FOUND"
}

// 500 Internal Server Error
{
  "error": "Internal server error",
  "code": "INTERNAL_ERROR"
}
```

---

## Security Architecture

### Defense-in-Depth

SecureBank implements **multiple layers of security**:

```
Layer 1: Input Validation (Frontend & Backend)
          ↓
Layer 2: Authentication (Token-based)
          ↓
Layer 3: Authorization (Resource ownership)
          ↓
Layer 4: Encryption (Password hashing, HTTPS)
          ↓
Layer 5: Database Security (Parameterized queries)
          ↓
Layer 6: Logging & Monitoring (Audit trail)
```

### Blue Team Security Features

**1. SQL Injection Prevention**
```python
# Use ORM with parameterized queries
user = BankUser.query.filter_by(username=username).first()

# Never use string formatting
# BAD: f"SELECT * FROM users WHERE username='{username}'"
```

**2. Authorization Checks**
```python
def check_account_ownership(account_id, user_id):
    account = BankAccount.query.get(account_id)
    if account.user_id != user_id:
        abort(403)
    return account
```

**3. Password Security**
```python
import bcrypt

# Hash password on registration
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Verify on login
if bcrypt.checkpw(password.encode(), stored_hash):
    # Password correct
```

**4. XSS Prevention**
```javascript
// Frontend: Use textContent, not innerHTML
element.textContent = userInput;

// Or sanitize with DOMPurify
element.innerHTML = DOMPurify.sanitize(userInput);

// Backend: Set Content Security Policy
response.headers['Content-Security-Policy'] = "default-src 'self'"
```

**5. CSRF Protection**
```python
# Generate token on login
csrf_token = secrets.token_urlsafe(32)
session['csrf_token'] = csrf_token

# Validate on state-changing requests
if request.headers.get('X-CSRF-Token') != session['csrf_token']:
    abort(403)
```

**6. Race Condition Prevention**
```python
# Use database locks
with db.session.begin_nested():
    account = BankAccount.query.with_for_update().get(account_id)
    # Modifications here are atomic
```

---

**Continue with remaining sections...**

This architecture guide demonstrates professional technical depth while remaining beginner-friendly. The structure explains complex concepts through simple analogies, code examples, and visual diagrams.

Would you like me to continue with the remaining sections (Data Flow Diagrams, Component Interaction, Design Patterns, etc.) to reach the full 200+ lines, or proceed to create the Remediation Guide?
