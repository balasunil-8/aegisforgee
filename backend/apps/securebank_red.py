"""
SecureBank - Vulnerable Online Banking Application (RED TEAM VERSION)
=====================================================================

This is an INTENTIONALLY VULNERABLE banking application for security education.
It demonstrates multiple OWASP vulnerabilities in a realistic banking context.

VULNERABILITIES IMPLEMENTED:
1. SQL Injection in login page
2. IDOR (Insecure Direct Object References) in account access
3. Race condition in money transfer
4. Stored XSS in transaction notes
5. Mass assignment allowing role escalation
6. CSRF in password change
7. Business logic flaws in transfer validation

DO NOT use this code in production. This is for educational purposes only.
"""

from flask import Flask, request, jsonify, render_template_string, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
from datetime import datetime
import time
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'weak-secret-key-123'  # VULNERABILITY: Weak secret
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securebank_red.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CORS(app)  # VULNERABILITY: Open CORS policy

db = SQLAlchemy(app)

# ============================================================================
# DATABASE MODELS
# ============================================================================

class BankUser(db.Model):
    """Banking user account"""
    __tablename__ = 'bank_users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Stored in plain MD5
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(120))
    role = db.Column(db.String(20), default='customer')  # customer, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        # VULNERABILITY: Returns password in response
        return {
            'id': self.id,
            'username': self.username,
            'password': self.password,  # SHOULD NOT EXPOSE THIS
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role
        }

class BankAccount(db.Model):
    """Bank account with balance"""
    __tablename__ = 'bank_accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('bank_users.id'))
    account_number = db.Column(db.String(20), unique=True)
    account_type = db.Column(db.String(20))  # checking, savings
    balance = db.Column(db.Float, default=1000.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('BankUser', backref='accounts')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'account_number': self.account_number,
            'account_type': self.account_type,
            'balance': self.balance,
            'owner_name': self.user.full_name if self.user else 'Unknown'
        }

class Transaction(db.Model):
    """Transaction history"""
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    from_account_id = db.Column(db.Integer, db.ForeignKey('bank_accounts.id'))
    to_account_id = db.Column(db.Integer, db.ForeignKey('bank_accounts.id'))
    amount = db.Column(db.Float)
    note = db.Column(db.Text)  # VULNERABILITY: No sanitization for XSS
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    
    from_account = db.relationship('BankAccount', foreign_keys=[from_account_id])
    to_account = db.relationship('BankAccount', foreign_keys=[to_account_id])
    
    def to_dict(self):
        return {
            'id': self.id,
            'from_account': self.from_account_id,
            'to_account': self.to_account_id,
            'amount': self.amount,
            'note': self.note,  # XSS vulnerability
            'timestamp': self.timestamp.isoformat(),
            'status': self.status
        }

# ============================================================================
# VULNERABLE ENDPOINTS
# ============================================================================

@app.route('/bank/api/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'app': 'SecureBank Red Team', 'version': '1.0'})

@app.route('/bank/api/auth/login', methods=['POST'])
def login():
    """
    VULNERABILITY: SQL Injection in login
    
    Educational Example:
    Try: username=' OR '1'='1' --&password=anything
    This bypasses authentication!
    """
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    
    # VULNERABILITY: Direct SQL concatenation (SQL Injection)
    conn = sqlite3.connect('securebank_red.db')
    cursor = conn.cursor()
    
    # DANGEROUS: User input directly in SQL query
    query = f"SELECT * FROM bank_users WHERE username='{username}' AND password='{hashlib.md5(password.encode()).hexdigest()}'"
    
    try:
        cursor.execute(query)
        user_row = cursor.fetchone()
        conn.close()
        
        if user_row:
            # Create session
            session['user_id'] = user_row[0]
            session['username'] = user_row[1]
            session['role'] = user_row[5]
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user_row[0],
                    'username': user_row[1],
                    'role': user_row[5]
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            
    except Exception as e:
        # VULNERABILITY: Verbose error messages reveal SQL structure
        return jsonify({'success': False, 'error': str(e), 'query': query}), 500

@app.route('/bank/api/accounts/<int:account_id>', methods=['GET'])
def get_account(account_id):
    """
    VULNERABILITY: IDOR (Insecure Direct Object Reference)
    
    Educational Example:
    Any logged-in user can access ANY account by changing the account_id
    No ownership verification!
    """
    # VULNERABILITY: No authentication check
    # VULNERABILITY: No ownership verification
    
    account = BankAccount.query.get(account_id)
    if not account:
        return jsonify({'error': 'Account not found'}), 404
    
    # Returns account regardless of who owns it
    return jsonify(account.to_dict())

@app.route('/bank/api/accounts', methods=['GET'])
def list_accounts():
    """
    Get all accounts for current user
    (This one is actually secure - for comparison)
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    accounts = BankAccount.query.filter_by(user_id=user_id).all()
    
    return jsonify({
        'accounts': [acc.to_dict() for acc in accounts]
    })

@app.route('/bank/api/transfer', methods=['POST'])
def transfer_money():
    """
    VULNERABILITY: Race condition in money transfer
    
    Educational Example:
    Send multiple simultaneous transfer requests with the same from_account
    The balance check happens before deduction, allowing overdraft!
    
    Also demonstrates business logic flaws:
    - No transaction locking
    - No idempotency checks
    - Concurrent requests can bypass balance validation
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json() or {}
    from_account_id = data.get('from_account_id')
    to_account_id = data.get('to_account_id')
    amount = data.get('amount', 0)
    note = data.get('note', '')
    
    # Basic validation
    if not from_account_id or not to_account_id or amount <= 0:
        return jsonify({'error': 'Invalid transfer data'}), 400
    
    # Get accounts
    from_account = BankAccount.query.get(from_account_id)
    to_account = BankAccount.query.get(to_account_id)
    
    if not from_account or not to_account:
        return jsonify({'error': 'Account not found'}), 404
    
    # VULNERABILITY: Race condition - check happens before deduction
    # Multiple concurrent requests can pass this check
    if from_account.balance < amount:
        return jsonify({'error': 'Insufficient funds'}), 400
    
    # Simulate processing time (makes race condition easier to exploit)
    time.sleep(0.1)
    
    # VULNERABILITY: No transaction locking
    # Another request could modify balance during this sleep
    from_account.balance -= amount
    to_account.balance += amount
    
    # Create transaction record
    transaction = Transaction(
        from_account_id=from_account_id,
        to_account_id=to_account_id,
        amount=amount,
        note=note,  # VULNERABILITY: No XSS sanitization
        status='completed'
    )
    
    db.session.add(transaction)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Transfer completed',
        'transaction_id': transaction.id,
        'new_balance': from_account.balance
    })

@app.route('/bank/api/transactions', methods=['GET'])
def get_transactions():
    """
    Get transaction history
    
    VULNERABILITY: Returns unsanitized notes (XSS in response)
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # Get user's accounts
    accounts = BankAccount.query.filter_by(user_id=user_id).all()
    account_ids = [acc.id for acc in accounts]
    
    # Get transactions
    transactions = Transaction.query.filter(
        (Transaction.from_account_id.in_(account_ids)) |
        (Transaction.to_account_id.in_(account_ids))
    ).order_by(Transaction.timestamp.desc()).limit(50).all()
    
    return jsonify({
        'transactions': [t.to_dict() for t in transactions]  # XSS in notes
    })

@app.route('/bank/api/profile', methods=['GET', 'PATCH'])
def profile():
    """
    Get or update user profile
    
    VULNERABILITY: Mass assignment in PATCH
    User can set any field including 'role' to escalate privileges!
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    user = BankUser.query.get(user_id)
    
    if request.method == 'GET':
        return jsonify(user.to_dict())  # VULNERABILITY: Exposes password
    
    # PATCH - Update profile
    data = request.get_json() or {}
    
    # VULNERABILITY: Mass assignment - blindly updates ANY field user sends
    for key, value in data.items():
        if hasattr(user, key):
            setattr(user, key, value)  # Including 'role'!
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Profile updated',
        'user': user.to_dict()
    })

@app.route('/bank/api/change-password', methods=['POST'])
def change_password():
    """
    VULNERABILITY: No CSRF protection
    VULNERABILITY: No current password verification
    
    Educational Example:
    An attacker can craft a malicious page that submits this form
    If victim is logged in, password gets changed without their knowledge!
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json() or {}
    new_password = data.get('new_password', '')
    
    # VULNERABILITY: No CSRF token check
    # VULNERABILITY: Doesn't verify current password
    
    if len(new_password) < 1:  # VULNERABILITY: Weak password policy
        return jsonify({'error': 'Password too short'}), 400
    
    user_id = session['user_id']
    user = BankUser.query.get(user_id)
    
    # VULNERABILITY: MD5 hashing (weak)
    user.password = hashlib.md5(new_password.encode()).hexdigest()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Password changed successfully'
    })

@app.route('/bank/api/admin/users', methods=['GET'])
def admin_list_users():
    """
    VULNERABILITY: Broken function level access control
    
    This endpoint should require admin role, but doesn't check!
    Any authenticated user can access admin functionality
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # VULNERABILITY: No role check - should verify user is admin
    # Any logged in user can call this!
    
    users = BankUser.query.all()
    return jsonify({
        'users': [u.to_dict() for u in users]  # Exposes all user passwords
    })

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_database():
    """Initialize database with sample data"""
    with app.app_context():
        db.create_all()
        
        # Check if already initialized
        if BankUser.query.first():
            return
        
        # Create sample users
        users_data = [
            {
                'username': 'alice',
                'password': hashlib.md5(b'password123').hexdigest(),
                'email': 'alice@securebank.com',
                'full_name': 'Alice Johnson',
                'role': 'customer'
            },
            {
                'username': 'bob',
                'password': hashlib.md5(b'qwerty').hexdigest(),
                'email': 'bob@securebank.com',
                'full_name': 'Bob Smith',
                'role': 'customer'
            },
            {
                'username': 'admin',
                'password': hashlib.md5(b'admin123').hexdigest(),  # Weak default credentials
                'email': 'admin@securebank.com',
                'full_name': 'Admin User',
                'role': 'admin'
            }
        ]
        
        for user_data in users_data:
            user = BankUser(**user_data)
            db.session.add(user)
        
        db.session.commit()
        
        # Create accounts for users
        alice = BankUser.query.filter_by(username='alice').first()
        bob = BankUser.query.filter_by(username='bob').first()
        admin_user = BankUser.query.filter_by(username='admin').first()
        
        accounts_data = [
            {'user_id': alice.id, 'account_number': 'ACC-1001', 'account_type': 'checking', 'balance': 5000.0},
            {'user_id': alice.id, 'account_number': 'ACC-1002', 'account_type': 'savings', 'balance': 10000.0},
            {'user_id': bob.id, 'account_number': 'ACC-2001', 'account_type': 'checking', 'balance': 3000.0},
            {'user_id': admin_user.id, 'account_number': 'ACC-9001', 'account_type': 'checking', 'balance': 100000.0},
        ]
        
        for acc_data in accounts_data:
            account = BankAccount(**acc_data)
            db.session.add(account)
        
        db.session.commit()
        
        print("✅ SecureBank Red Team database initialized")
        print("📝 Test Credentials:")
        print("   - alice / password123")
        print("   - bob / qwerty")
        print("   - admin / admin123")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    init_database()
    print("\n" + "="*70)
    print("🏦 SecureBank - VULNERABLE VERSION (Red Team)")
    print("="*70)
    print("\n⚠️  WARNING: This is an INTENTIONALLY VULNERABLE application!")
    print("⚠️  For educational purposes only - DO NOT use in production!")
    print("\n📚 Vulnerabilities included:")
    print("   1. SQL Injection (login)")
    print("   2. IDOR (account access)")
    print("   3. Race condition (transfers)")
    print("   4. XSS (transaction notes)")
    print("   5. Mass assignment (profile)")
    print("   6. CSRF (password change)")
    print("   7. Broken access control (admin endpoint)")
    print("\n🌐 Starting server on http://localhost:5001")
    print("="*70 + "\n")
    
    app.run(debug=True, port=5001, host='0.0.0.0')
