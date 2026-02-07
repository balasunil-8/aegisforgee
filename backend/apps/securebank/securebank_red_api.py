"""
SecureBank Red Team API - VULNERABLE VERSION
WARNING: This code contains intentional security vulnerabilities for educational purposes.
NEVER use this code in production.

Demonstrates 6 major vulnerabilities:
1. SQL Injection (Login)
2. IDOR - Insecure Direct Object References (Account Access)
3. Race Condition (Money Transfer)
4. XSS - Cross-Site Scripting (Transaction Notes)
5. Mass Assignment (Profile Update)
6. CSRF - Cross-Site Request Forgery (Settings)
"""

from flask import Flask, request, jsonify, session, make_response
from flask_cors import CORS
import sqlite3
from datetime import datetime
import os
import time
import threading

# Database configuration
DB_PATH = os.path.join(os.path.dirname(__file__), 'securebank.db')

# Lock for race condition demo (intentionally not used in vulnerable version)
transfer_lock = threading.Lock()


def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def create_red_team_api():
    """Create Flask app with vulnerable endpoints"""
    app = Flask(__name__)
    app.secret_key = 'insecure-secret-key-123'  # VULNERABLE: Weak secret key
    
    # VULNERABLE: Wide open CORS
    CORS(app, supports_credentials=True, resources={
        r"/api/red/securebank/*": {"origins": "*"}
    })
    
    # ============================================================================
    # VULNERABILITY #1: SQL INJECTION (Login Page)
    # ============================================================================
    
    @app.route('/api/red/securebank/login', methods=['POST'])
    def red_login():
        """
        VULNERABLE: SQL Injection in login
        Attack: username = admin' OR '1'='1'--
        """
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        
        # VULNERABLE: Direct string concatenation - SQL Injection
        query = f"SELECT * FROM bank_users WHERE username='{username}' AND password='{password}'"
        
        try:
            conn = get_db()
            cursor = conn.execute(query)  # DANGEROUS: No parameterization
            user = cursor.fetchone()
            conn.close()
            
            if user:
                # Store user in session
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                
                return jsonify({
                    'success': True,
                    'user': {
                        'id': user['id'],
                        'username': user['username'],
                        'full_name': user['full_name'],
                        'role': user['role']
                    },
                    'message': 'Login successful'
                }), 200
            else:
                return jsonify({
                    'success': False,
                    'error': 'Invalid credentials'
                }), 401
                
        except Exception as e:
            # VULNERABLE: Leaking error details
            return jsonify({
                'success': False,
                'error': str(e),
                'query': query  # VULNERABLE: Leaking query structure
            }), 500
    
    @app.route('/api/red/securebank/logout', methods=['POST'])
    def red_logout():
        """Logout endpoint"""
        session.clear()
        return jsonify({'success': True, 'message': 'Logged out'}), 200
    
    @app.route('/api/red/securebank/session', methods=['GET'])
    def red_get_session():
        """Get current session info"""
        if 'user_id' in session:
            return jsonify({
                'authenticated': True,
                'user': {
                    'id': session.get('user_id'),
                    'username': session.get('username'),
                    'role': session.get('role')
                }
            }), 200
        return jsonify({'authenticated': False}), 200
    
    # ============================================================================
    # VULNERABILITY #2: IDOR - Insecure Direct Object References (Accounts)
    # ============================================================================
    
    @app.route('/api/red/securebank/accounts', methods=['GET'])
    def red_get_accounts():
        """
        Get user's accounts
        Should only return accounts owned by authenticated user
        """
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
    
    @app.route('/api/red/securebank/account/<int:account_id>', methods=['GET'])
    def red_get_account(account_id):
        """
        VULNERABLE: IDOR - No authorization check
        Attack: Change account_id in URL to access other users' accounts
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        # VULNERABLE: No ownership verification
        conn = get_db()
        cursor = conn.execute(
            'SELECT * FROM bank_accounts WHERE id = ?',
            (account_id,)
        )
        account = cursor.fetchone()
        conn.close()
        
        if account:
            return jsonify({
                'success': True,
                'account': dict(account)
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Account not found'
            }), 404
    
    # ============================================================================
    # VULNERABILITY #3: RACE CONDITION (Money Transfer)
    # ============================================================================
    
    @app.route('/api/red/securebank/transfer', methods=['POST'])
    def red_transfer():
        """
        VULNERABLE: Race condition in money transfer
        Attack: Send multiple concurrent transfer requests
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        from_account_num = data.get('from_account')
        to_account_num = data.get('to_account')
        amount = float(data.get('amount', 0))
        note = data.get('note', '')
        
        if amount <= 0:
            return jsonify({'success': False, 'error': 'Invalid amount'}), 400
        
        try:
            conn = get_db()
            
            # VULNERABLE: No locking mechanism - Race condition possible
            # Step 1: Check balance (time gap allows concurrent requests)
            cursor = conn.execute(
                'SELECT * FROM bank_accounts WHERE account_number = ?',
                (from_account_num,)
            )
            from_account = cursor.fetchone()
            
            if not from_account:
                conn.close()
                return jsonify({'success': False, 'error': 'Source account not found'}), 404
            
            # Verify ownership
            if from_account['user_id'] != session['user_id']:
                conn.close()
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            # Check destination account
            cursor = conn.execute(
                'SELECT * FROM bank_accounts WHERE account_number = ?',
                (to_account_num,)
            )
            to_account = cursor.fetchone()
            
            if not to_account:
                conn.close()
                return jsonify({'success': False, 'error': 'Destination account not found'}), 404
            
            # VULNERABLE: Balance check happens here, but update happens later
            # Multiple requests can pass this check before any update occurs
            if from_account['balance'] < amount:
                conn.close()
                return jsonify({'success': False, 'error': 'Insufficient funds'}), 400
            
            # Simulate processing time (makes race condition more obvious)
            time.sleep(0.1)
            
            # Step 2: Deduct from source (VULNERABLE: No transaction isolation)
            conn.execute(
                'UPDATE bank_accounts SET balance = balance - ? WHERE account_number = ?',
                (amount, from_account_num)
            )
            
            # Step 3: Add to destination
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
            return jsonify({'success': False, 'error': str(e)}), 500
    
    # ============================================================================
    # VULNERABILITY #4: XSS - Cross-Site Scripting (Transaction Notes)
    # ============================================================================
    
    @app.route('/api/red/securebank/transactions', methods=['GET'])
    def red_get_transactions():
        """
        Get transactions for user's accounts
        VULNERABLE: Returns unsanitized transaction notes (XSS in frontend)
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
        
        # VULNERABLE: No output encoding - notes can contain XSS payloads
        return jsonify({
            'success': True,
            'transactions': transactions
        }), 200
    
    @app.route('/api/red/securebank/transaction/<int:transaction_id>/note', methods=['PUT'])
    def red_update_transaction_note(transaction_id):
        """
        VULNERABLE: Allows adding XSS payloads to transaction notes
        Attack: note = "<script>alert(document.cookie)</script>"
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        note = data.get('note', '')
        
        # VULNERABLE: No input sanitization
        conn = get_db()
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
    # VULNERABILITY #5: MASS ASSIGNMENT (Profile Update)
    # ============================================================================
    
    @app.route('/api/red/securebank/profile', methods=['GET'])
    def red_get_profile():
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
    
    # ============================================================================
    # VULNERABILITY #6: CSRF - Cross-Site Request Forgery (Settings)
    # ============================================================================
    
    @app.route('/api/red/securebank/settings', methods=['GET'])
    def red_get_settings():
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
    
    @app.route('/api/red/securebank/settings', methods=['POST'])
    def red_update_settings():
        """
        VULNERABLE: No CSRF protection
        Attack: Create malicious page that submits form when victim visits
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        data = request.get_json()
        
        # VULNERABLE: No CSRF token validation
        email_notifications = data.get('email_notifications', True)
        sms_notifications = data.get('sms_notifications', False)
        transaction_alerts = data.get('transaction_alerts', True)
        login_alerts = data.get('login_alerts', True)
        theme = data.get('theme', 'light')
        language = data.get('language', 'en')
        
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
        
        return jsonify({
            'success': True,
            'message': 'Settings updated'
        }), 200
    
    # ============================================================================
    # ADDITIONAL ENDPOINTS
    # ============================================================================
    
    @app.route('/api/red/securebank/beneficiaries', methods=['GET'])
    def red_get_beneficiaries():
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
    
    @app.route('/api/red/securebank/beneficiaries', methods=['POST'])
    def red_add_beneficiary():
        """Add new beneficiary"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        data = request.get_json()
        
        name = data.get('name', '')
        account_number = data.get('account_number', '')
        bank_name = data.get('bank_name', 'AegisBank')
        nickname = data.get('nickname', '')
        
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
    
    @app.route('/api/red/securebank/dashboard', methods=['GET'])
    def red_get_dashboard():
        """Get dashboard data"""
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
    app = create_red_team_api()
    print("🔴 SecureBank Red Team API (VULNERABLE) starting...")
    print("⚠️  WARNING: This application contains intentional vulnerabilities")
    print("🔗 Base URL: http://localhost:5000/api/red/securebank")
    # NOTE: debug=True is INTENTIONALLY enabled for educational purposes
    # This is a VULNERABILITY - allows access to Python debugger
    # NEVER use debug=True in production!
    app.run(debug=True, port=5000)  # nosec - intentional vulnerability
