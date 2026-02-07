"""
SecureBank Blue Team API - SECURE VERSION
Demonstrates proper security implementations to prevent common vulnerabilities.

Security Features Implemented:
1. Parameterized queries (prevents SQL Injection)
2. Authorization checks (prevents IDOR)
3. Database transactions with locking (prevents Race Conditions)
4. Output encoding (prevents XSS)
5. Field whitelisting (prevents Mass Assignment)
6. CSRF tokens (prevents CSRF attacks)
"""

from flask import Flask, request, jsonify, session
from flask_cors import CORS
import sqlite3
from datetime import datetime
import os
import secrets
import threading
import hashlib
import re

# Database configuration
DB_PATH = os.path.join(os.path.dirname(__file__), 'securebank.db')

# Thread lock for preventing race conditions
transfer_lock = threading.Lock()


def get_db():
    """Get database connection with row factory"""
    conn = sqlite3.connect(DB_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    # Enable Write-Ahead Logging for better concurrency
    conn.execute('PRAGMA journal_mode=WAL')
    return conn


def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_phone(phone):
    """Validate phone format"""
    pattern = r'^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$'
    return re.match(pattern, phone) is not None


def escape_html(text):
    """HTML entity encoding to prevent XSS"""
    if not text:
        return text
    html_escape_table = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
        "/": "&#x2F;"
    }
    return "".join(html_escape_table.get(c, c) for c in str(text))


def create_blue_team_api():
    """Create Flask app with secure endpoints"""
    app = Flask(__name__)
    app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    
    # Secure CORS configuration
    CORS(app, supports_credentials=True, resources={
        r"/api/blue/securebank/*": {
            "origins": ["http://localhost:3000", "http://localhost:5000"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "X-CSRF-Token"]
        }
    })
    
    # Add security headers
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses"""
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    # ============================================================================
    # SECURITY FIX #1: SQL Injection Prevention (Parameterized Queries)
    # ============================================================================
    
    @app.route('/api/blue/securebank/login', methods=['POST'])
    def blue_login():
        """
        SECURE: Parameterized queries prevent SQL injection
        Uses placeholders (?) instead of string concatenation
        """
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        
        # Input validation
        if not username or not password:
            return jsonify({
                'success': False,
                'error': 'Username and password required'
            }), 400
        
        # SECURE: Parameterized query - SQL Injection prevented
        query = "SELECT * FROM bank_users WHERE username = ? AND password = ?"
        
        try:
            conn = get_db()
            cursor = conn.execute(query, (username, password))
            user = cursor.fetchone()
            conn.close()
            
            if user:
                # Store user in session
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                
                # Generate CSRF token
                csrf_token = secrets.token_hex(32)
                session['csrf_token'] = csrf_token
                
                # Update last login
                conn = get_db()
                conn.execute(
                    'UPDATE bank_users SET last_login = ? WHERE id = ?',
                    (datetime.now().isoformat(), user['id'])
                )
                conn.commit()
                conn.close()
                
                return jsonify({
                    'success': True,
                    'user': {
                        'id': user['id'],
                        'username': user['username'],
                        'full_name': user['full_name'],
                        'role': user['role']
                    },
                    'csrf_token': csrf_token,
                    'message': 'Login successful'
                }), 200
            else:
                return jsonify({
                    'success': False,
                    'error': 'Invalid credentials'
                }), 401
                
        except Exception as e:
            # SECURE: Don't leak sensitive error details
            return jsonify({
                'success': False,
                'error': 'An error occurred during login'
            }), 500
    
    @app.route('/api/blue/securebank/logout', methods=['POST'])
    def blue_logout():
        """Logout endpoint with CSRF protection"""
        # Verify CSRF token
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
        
        session.clear()
        return jsonify({'success': True, 'message': 'Logged out'}), 200
    
    @app.route('/api/blue/securebank/session', methods=['GET'])
    def blue_get_session():
        """Get current session info"""
        if 'user_id' in session:
            return jsonify({
                'authenticated': True,
                'user': {
                    'id': session.get('user_id'),
                    'username': session.get('username'),
                    'role': session.get('role')
                },
                'csrf_token': session.get('csrf_token')
            }), 200
        return jsonify({'authenticated': False}), 200
    
    @app.route('/api/blue/securebank/csrf-token', methods=['GET'])
    def blue_get_csrf_token():
        """Get or generate CSRF token"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        
        return jsonify({
            'success': True,
            'csrf_token': session['csrf_token']
        }), 200
    
    # ============================================================================
    # SECURITY FIX #2: IDOR Prevention (Authorization Checks)
    # ============================================================================
    
    @app.route('/api/blue/securebank/accounts', methods=['GET'])
    def blue_get_accounts():
        """Get user's accounts with proper authorization"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        conn = get_db()
        cursor = conn.execute(
            'SELECT * FROM bank_accounts WHERE user_id = ?',
            (user_id,)
        )
        accounts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'accounts': accounts}), 200
    
    @app.route('/api/blue/securebank/account/<int:account_id>', methods=['GET'])
    def blue_get_account(account_id):
        """
        SECURE: Verifies ownership before returning account
        Prevents IDOR by checking user_id matches
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        # SECURE: Verify ownership with user_id in query
        conn = get_db()
        cursor = conn.execute(
            'SELECT * FROM bank_accounts WHERE id = ? AND user_id = ?',
            (account_id, user_id)
        )
        account = cursor.fetchone()
        conn.close()
        
        if account:
            return jsonify({
                'success': True,
                'account': dict(account)
            }), 200
        else:
            # Don't reveal if account exists or not (security by obscurity)
            return jsonify({
                'success': False,
                'error': 'Account not found or access denied'
            }), 404
    
    # ============================================================================
    # SECURITY FIX #3: Race Condition Prevention (Database Locking)
    # ============================================================================
    
    @app.route('/api/blue/securebank/transfer', methods=['POST'])
    def blue_transfer():
        """
        SECURE: Uses transaction with locking to prevent race conditions
        Implements mutex lock and BEGIN EXCLUSIVE transaction
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        # Verify CSRF token
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
        
        data = request.get_json()
        from_account_num = data.get('from_account')
        to_account_num = data.get('to_account')
        amount = float(data.get('amount', 0))
        note = data.get('note', '')
        
        # Input validation
        if amount <= 0:
            return jsonify({'success': False, 'error': 'Invalid amount'}), 400
        
        # Sanitize note to prevent XSS
        note = escape_html(note)
        
        # SECURE: Use mutex lock to prevent concurrent access
        with transfer_lock:
            try:
                conn = get_db()
                
                # SECURE: BEGIN EXCLUSIVE transaction for atomic operations
                conn.execute('BEGIN EXCLUSIVE')
                
                # Get source account with SELECT FOR UPDATE (row-level lock)
                cursor = conn.execute(
                    'SELECT * FROM bank_accounts WHERE account_number = ?',
                    (from_account_num,)
                )
                from_account = cursor.fetchone()
                
                if not from_account:
                    conn.rollback()
                    conn.close()
                    return jsonify({'success': False, 'error': 'Source account not found'}), 404
                
                # Verify ownership
                if from_account['user_id'] != session['user_id']:
                    conn.rollback()
                    conn.close()
                    return jsonify({'success': False, 'error': 'Unauthorized'}), 403
                
                # Get destination account
                cursor = conn.execute(
                    'SELECT * FROM bank_accounts WHERE account_number = ?',
                    (to_account_num,)
                )
                to_account = cursor.fetchone()
                
                if not to_account:
                    conn.rollback()
                    conn.close()
                    return jsonify({'success': False, 'error': 'Destination account not found'}), 404
                
                # SECURE: Check balance within transaction
                if from_account['balance'] < amount:
                    conn.rollback()
                    conn.close()
                    return jsonify({'success': False, 'error': 'Insufficient funds'}), 400
                
                # SECURE: All operations within same transaction - atomic
                # Deduct from source
                conn.execute(
                    'UPDATE bank_accounts SET balance = balance - ? WHERE account_number = ?',
                    (amount, from_account_num)
                )
                
                # Add to destination
                conn.execute(
                    'UPDATE bank_accounts SET balance = balance + ? WHERE account_number = ?',
                    (amount, to_account_num)
                )
                
                # Create transaction record
                reference = f"TXN{datetime.now().strftime('%Y%m%d%H%M%S')}{from_account['id']}"
                conn.execute('''
                    INSERT INTO transactions (from_account_id, to_account_id, from_account_number, 
                                            to_account_number, amount, type, status, note, reference, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (from_account['id'], to_account['id'], from_account_num, to_account_num,
                      amount, 'transfer', 'completed', note, reference, datetime.now().isoformat()))
                
                # SECURE: Commit all changes atomically
                conn.commit()
                conn.close()
                
                return jsonify({
                    'success': True,
                    'message': 'Transfer successful',
                    'reference': reference
                }), 200
                
            except Exception as e:
                if conn:
                    conn.rollback()
                    conn.close()
                return jsonify({'success': False, 'error': 'Transfer failed'}), 500
    
    # ============================================================================
    # SECURITY FIX #4: XSS Prevention (Output Encoding)
    # ============================================================================
    
    @app.route('/api/blue/securebank/transactions', methods=['GET'])
    def blue_get_transactions():
        """
        Get transactions with HTML-encoded notes
        SECURE: Applies output encoding to prevent XSS
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        # Get user's account IDs
        conn = get_db()
        cursor = conn.execute(
            'SELECT id FROM bank_accounts WHERE user_id = ?',
            (user_id,)
        )
        account_ids = [row['id'] for row in cursor.fetchall()]
        
        if not account_ids:
            conn.close()
            return jsonify({'success': True, 'transactions': []}), 200
        
        # Get transactions
        placeholders = ','.join('?' * len(account_ids))
        query = f'''
            SELECT * FROM transactions 
            WHERE from_account_id IN ({placeholders}) OR to_account_id IN ({placeholders})
            ORDER BY timestamp DESC
            LIMIT 50
        '''
        cursor = conn.execute(query, account_ids + account_ids)
        transactions = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        # SECURE: Encode HTML entities in notes to prevent XSS
        for transaction in transactions:
            if transaction.get('note'):
                transaction['note'] = escape_html(transaction['note'])
        
        return jsonify({
            'success': True,
            'transactions': transactions
        }), 200
    
    @app.route('/api/blue/securebank/transaction/<int:transaction_id>/note', methods=['PUT'])
    def blue_update_transaction_note(transaction_id):
        """
        SECURE: Sanitizes input before storing
        Prevents XSS by encoding HTML entities
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        # Verify CSRF token
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
        
        data = request.get_json()
        note = data.get('note', '')
        
        # SECURE: HTML entity encoding before storing
        note = escape_html(note)
        
        # Verify transaction belongs to user
        conn = get_db()
        cursor = conn.execute('''
            SELECT t.* FROM transactions t
            JOIN bank_accounts ba ON (t.from_account_id = ba.id OR t.to_account_id = ba.id)
            WHERE t.id = ? AND ba.user_id = ?
        ''', (transaction_id, session['user_id']))
        transaction = cursor.fetchone()
        
        if not transaction:
            conn.close()
            return jsonify({'success': False, 'error': 'Transaction not found'}), 404
        
        conn.execute(
            'UPDATE transactions SET note = ? WHERE id = ?',
            (note, transaction_id)
        )
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Note updated'
        }), 200
    
    # ============================================================================
    # SECURITY FIX #5: Mass Assignment Prevention (Field Whitelisting)
    # ============================================================================
    
    @app.route('/api/blue/securebank/profile', methods=['GET'])
    def blue_get_profile():
        """Get user profile"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        conn = get_db()
        cursor = conn.execute(
            'SELECT id, username, email, full_name, phone, address, role FROM bank_users WHERE id = ?',
            (user_id,)
        )
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return jsonify({
                'success': True,
                'profile': dict(user)
            }), 200
        else:
            return jsonify({'success': False, 'error': 'User not found'}), 404
    
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
    
    # ============================================================================
    # SECURITY FIX #6: CSRF Prevention (Token Validation)
    # ============================================================================
    
    @app.route('/api/blue/securebank/settings', methods=['GET'])
    def blue_get_settings():
        """Get user settings"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        conn = get_db()
        cursor = conn.execute(
            'SELECT * FROM user_settings WHERE user_id = ?',
            (user_id,)
        )
        settings = cursor.fetchone()
        conn.close()
        
        if settings:
            return jsonify({
                'success': True,
                'settings': dict(settings)
            }), 200
        else:
            # Create default settings
            conn = get_db()
            conn.execute('''
                INSERT INTO user_settings (user_id, email_notifications, sms_notifications,
                                          transaction_alerts, login_alerts, theme, language)
                VALUES (?, 1, 0, 1, 1, 'light', 'en')
            ''', (user_id,))
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'settings': {
                    'email_notifications': True,
                    'sms_notifications': False,
                    'transaction_alerts': True,
                    'login_alerts': True,
                    'theme': 'light',
                    'language': 'en'
                }
            }), 200
    
    @app.route('/api/blue/securebank/settings', methods=['POST'])
    def blue_update_settings():
        """
        SECURE: Validates CSRF token before processing request
        Prevents CSRF attacks by requiring valid token
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        # SECURE: CSRF token validation
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return jsonify({
                'success': False,
                'error': 'Invalid CSRF token - possible CSRF attack detected'
            }), 403
        
        user_id = session['user_id']
        data = request.get_json()
        
        # Extract settings with defaults
        email_notifications = bool(data.get('email_notifications', True))
        sms_notifications = bool(data.get('sms_notifications', False))
        transaction_alerts = bool(data.get('transaction_alerts', True))
        login_alerts = bool(data.get('login_alerts', True))
        theme = data.get('theme', 'light')
        language = data.get('language', 'en')
        
        # Validate theme and language
        if theme not in ['light', 'dark']:
            theme = 'light'
        if language not in ['en', 'es', 'fr', 'de']:
            language = 'en'
        
        conn = get_db()
        conn.execute('''
            UPDATE user_settings 
            SET email_notifications = ?, sms_notifications = ?, transaction_alerts = ?,
                login_alerts = ?, theme = ?, language = ?
            WHERE user_id = ?
        ''', (email_notifications, sms_notifications, transaction_alerts,
              login_alerts, theme, language, user_id))
        conn.commit()
        conn.close()
        
        # SECURE: Generate new CSRF token after state-changing operation
        new_csrf_token = secrets.token_hex(32)
        session['csrf_token'] = new_csrf_token
        
        return jsonify({
            'success': True,
            'message': 'Settings updated',
            'new_csrf_token': new_csrf_token
        }), 200
    
    # ============================================================================
    # ADDITIONAL SECURE ENDPOINTS
    # ============================================================================
    
    @app.route('/api/blue/securebank/beneficiaries', methods=['GET'])
    def blue_get_beneficiaries():
        """Get user's beneficiaries"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        conn = get_db()
        cursor = conn.execute(
            'SELECT * FROM beneficiaries WHERE user_id = ? ORDER BY added_date DESC',
            (user_id,)
        )
        beneficiaries = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({
            'success': True,
            'beneficiaries': beneficiaries
        }), 200
    
    @app.route('/api/blue/securebank/beneficiaries', methods=['POST'])
    def blue_add_beneficiary():
        """Add new beneficiary with CSRF protection"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        # Verify CSRF token
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
        
        user_id = session['user_id']
        data = request.get_json()
        
        name = escape_html(data.get('name', ''))
        account_number = data.get('account_number', '').strip()
        bank_name = escape_html(data.get('bank_name', 'AegisBank'))
        nickname = escape_html(data.get('nickname', ''))
        
        if not name or not account_number:
            return jsonify({'success': False, 'error': 'Name and account number required'}), 400
        
        conn = get_db()
        cursor = conn.execute('''
            INSERT INTO beneficiaries (user_id, name, account_number, bank_name, nickname, added_date)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, name, account_number, bank_name, nickname, datetime.now().isoformat()))
        conn.commit()
        beneficiary_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Beneficiary added',
            'beneficiary_id': beneficiary_id
        }), 201
    
    @app.route('/api/blue/securebank/dashboard', methods=['GET'])
    def blue_get_dashboard():
        """Get dashboard data with proper authorization"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        conn = get_db()
        
        # Get accounts
        cursor = conn.execute(
            'SELECT * FROM bank_accounts WHERE user_id = ?',
            (user_id,)
        )
        accounts = [dict(row) for row in cursor.fetchall()]
        
        # Get recent transactions
        account_ids = [acc['id'] for acc in accounts]
        if account_ids:
            placeholders = ','.join('?' * len(account_ids))
            query = f'''
                SELECT * FROM transactions 
                WHERE from_account_id IN ({placeholders}) OR to_account_id IN ({placeholders})
                ORDER BY timestamp DESC
                LIMIT 5
            '''
            cursor = conn.execute(query, account_ids + account_ids)
            transactions = [dict(row) for row in cursor.fetchall()]
            
            # Encode transaction notes
            for transaction in transactions:
                if transaction.get('note'):
                    transaction['note'] = escape_html(transaction['note'])
        else:
            transactions = []
        
        # Get user info
        cursor = conn.execute(
            'SELECT username, full_name, email FROM bank_users WHERE id = ?',
            (user_id,)
        )
        user_info = dict(cursor.fetchone())
        
        conn.close()
        
        # Calculate total balance
        total_balance = sum(acc['balance'] for acc in accounts)
        
        return jsonify({
            'success': True,
            'dashboard': {
                'user': user_info,
                'accounts': accounts,
                'recent_transactions': transactions,
                'total_balance': total_balance,
                'account_count': len(accounts)
            }
        }), 200
    
    return app


if __name__ == '__main__':
    app = create_blue_team_api()
    print("🔵 SecureBank Blue Team API (SECURE) starting...")
    print("✅ All security features enabled")
    print("🔗 Base URL: http://localhost:5001/api/blue/securebank")
    app.run(debug=False, port=5001)  # Debug disabled in production
