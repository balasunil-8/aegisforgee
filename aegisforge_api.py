"""
AegisForge Red Team - Vulnerable Endpoints
Intentionally vulnerable endpoints for security testing and education
Version: 2.0
WARNING: These endpoints are intentionally insecure. Never deploy to production.
"""

from flask import Flask, request, jsonify, render_template_string
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import sqlite3
import pickle
import subprocess
import requests
import xml.etree.ElementTree as ET
import os
import json
import time
from datetime import datetime, timedelta
from functools import wraps
import hashlib

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'insecure-secret-key-123'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-123'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['DEBUG'] = True  # VULNERABLE: Debug mode enabled

jwt = JWTManager(app)
CORS(app, resources={r"/*": {"origins": "*"}})  # VULNERABLE: CORS wide open

# Simple in-memory storage
users_db = {
    1: {'id': 1, 'username': 'admin', 'password': 'admin123', 'role': 'admin', 'is_admin': True},
    2: {'id': 2, 'username': 'user1', 'password': 'password', 'role': 'user', 'is_admin': False}
}
messages_db = {
    1: {'id': 1, 'user_id': 1, 'text': 'Admin secret message', 'private': True},
    2: {'id': 2, 'user_id': 2, 'text': 'User private message', 'private': True}
}
orders_db = {}
coupons_used = []

# ============================================================================
# SQL INJECTION VULNERABILITIES (3 ENDPOINTS)
# ============================================================================

@app.route('/api/injection/sqli/boolean', methods=['GET'])
def red_sqli_boolean():
    """VULNERABLE: SQL injection via string concatenation"""
    username = request.args.get('username', '')
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}'"
    
    try:
        conn = sqlite3.connect('pentestlab.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query)  # DANGEROUS: Injectable query
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({
            'ok': True,
            'results': results,
            'query_executed': query,  # VULNERABLE: Leaking query structure
            'count': len(results)
        }), 200
    except Exception as e:
        return jsonify({
            'error': str(e),  # VULNERABLE: Leaking error details
            'query': query
        }), 500


@app.route('/api/injection/sqli/time-based', methods=['GET'])
def red_sqli_time_based():
    """VULNERABLE: Time-based blind SQL injection"""
    user_id = request.args.get('id', '1')
    
    # VULNERABLE: Injectable time-based query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    try:
        conn = sqlite3.connect('pentestlab.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query)
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({
            'ok': True,
            'results': results,
            'vulnerable_to': 'Time-based blind SQLi'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/injection/sqli/union', methods=['GET'])
def red_sqli_union():
    """VULNERABLE: UNION-based SQL injection"""
    search = request.args.get('search', '')
    
    # VULNERABLE: UNION attack possible
    query = f"SELECT id, username, email FROM users WHERE username LIKE '%{search}%'"
    
    try:
        conn = sqlite3.connect('pentestlab.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query)
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({
            'ok': True,
            'results': results,
            'hint': 'Try UNION SELECT to extract data from other tables'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e), 'query': query}), 500


# ============================================================================
# XSS VULNERABILITIES (3 ENDPOINTS)
# ============================================================================

@app.route('/api/xss/reflected', methods=['GET'])
def red_xss_reflected():
    """VULNERABLE: Reflected XSS via unescaped user input"""
    message = request.args.get('message', 'Hello')
    
    # VULNERABLE: No output encoding
    html = f"""
    <html>
    <head><title>Message Display</title></head>
    <body>
    <h1>Your Message:</h1>
    <p>{message}</p>
    <div class="warning">
        <p>⚠️ This endpoint is vulnerable to XSS!</p>
        <p>Payload: {message}</p>
    </div>
    </body>
    </html>
    """
    return app.response_class(response=html, mimetype='text/html')


@app.route('/api/xss/stored', methods=['POST'])
def red_xss_stored():
    """VULNERABLE: Stored XSS in comments"""
    data = request.get_json() or {}
    comment = data.get('comment', '')
    
    # VULNERABLE: Store malicious content without sanitization
    # In real app, this would go to a database
    stored_comment = {
        'id': len(messages_db) + 1,
        'comment': comment,  # DANGEROUS: No sanitization
        'timestamp': datetime.utcnow().isoformat()
    }
    
    return jsonify({
        'ok': True,
        'stored': stored_comment,
        'warning': 'Stored without sanitization - vulnerable to XSS'
    }), 200


@app.route('/api/xss/dom', methods=['GET'])
def red_xss_dom():
    """VULNERABLE: DOM-based XSS"""
    user_data = request.args.get('data', '')
    
    html = f"""
    <html>
    <head><title>User Profile</title></head>
    <body>
    <h1>Profile Data</h1>
    <div id="profile"></div>
    <script>
        // VULNERABLE: Using innerHTML with user input
        document.getElementById('profile').innerHTML = '{user_data}';
    </script>
    </body>
    </html>
    """
    return app.response_class(response=html, mimetype='text/html')


# ============================================================================
# ACCESS CONTROL VULNERABILITIES (4 ENDPOINTS)
# ============================================================================

@app.route('/api/access/idor/<int:user_id>', methods=['GET'])
def red_idor_access(user_id):
    """VULNERABLE: IDOR - No ownership validation"""
    # VULNERABLE: No check if current user owns this resource
    user = users_db.get(user_id)
    
    if user:
        return jsonify({
            'ok': True,
            'user': user,  # VULNERABLE: Returns all data including password
            'vulnerability': 'IDOR - Broken Object Level Authorization'
        }), 200
    
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/access/privilege-escalation', methods=['PUT'])
def red_privilege_escalation():
    """VULNERABLE: Privilege escalation via mass assignment"""
    data = request.get_json() or {}
    user_id = data.get('user_id', 2)
    
    # VULNERABLE: No authorization check, accepts any field
    if user_id in users_db:
        users_db[user_id].update(data)  # DANGEROUS: Mass assignment
        
        return jsonify({
            'ok': True,
            'user': users_db[user_id],
            'vulnerability': 'Privilege escalation via mass assignment'
        }), 200
    
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/access/bola/<int:message_id>', methods=['GET'])
def red_bola(message_id):
    """VULNERABLE: BOLA - Broken Object Level Authorization"""
    # VULNERABLE: No ownership check
    message = messages_db.get(message_id)
    
    if message:
        return jsonify({
            'ok': True,
            'message': message,
            'vulnerability': 'BOLA - No ownership validation'
        }), 200
    
    return jsonify({'error': 'Message not found'}), 404


@app.route('/api/access/horizontal-privilege', methods=['GET'])
def red_horizontal_privilege():
    """VULNERABLE: Horizontal privilege escalation"""
    target_user_id = request.args.get('user_id', type=int, default=1)
    
    # VULNERABLE: No check if requester should access this user's data
    user = users_db.get(target_user_id)
    
    if user:
        return jsonify({
            'ok': True,
            'user': user,
            'vulnerability': 'Horizontal privilege escalation'
        }), 200
    
    return jsonify({'error': 'User not found'}), 404


# ============================================================================
# AUTHENTICATION VULNERABILITIES (4 ENDPOINTS)
# ============================================================================

@app.route('/api/auth/login', methods=['POST'])
def red_login():
    """VULNERABLE: Weak authentication - no rate limiting, plain text comparison"""
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    
    # VULNERABLE: No rate limiting, timing attack possible
    for user_id, user in users_db.items():
        if user['username'] == username and user['password'] == password:  # VULNERABLE: Plain text comparison
            token = create_access_token(identity=username)
            return jsonify({
                'ok': True,
                'token': token,
                'user': user,  # VULNERABLE: Returns password in response
                'vulnerability': 'Weak authentication'
            }), 200
    
    # VULNERABLE: Detailed error message aids enumeration
    return jsonify({'error': 'Invalid username or password', 'exists': username in [u['username'] for u in users_db.values()]}), 401


@app.route('/api/auth/register', methods=['POST'])
def red_register():
    """VULNERABLE: Weak password policy"""
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')  # VULNERABLE: No password complexity check
    
    # VULNERABLE: Accepts weak passwords
    new_id = max(users_db.keys()) + 1
    users_db[new_id] = {
        'id': new_id,
        'username': username,
        'password': password,  # VULNERABLE: Plain text password storage
        'role': 'user',
        'is_admin': False
    }
    
    return jsonify({
        'ok': True,
        'user': users_db[new_id],
        'vulnerability': 'Weak password policy + plain text storage'
    }), 201


@app.route('/api/auth/password-reset', methods=['POST'])
def red_password_reset():
    """VULNERABLE: Insecure password reset"""
    data = request.get_json() or {}
    username = data.get('username', '')
    
    # VULNERABLE: No token verification, anyone can reset any password
    for user_id, user in users_db.items():
        if user['username'] == username:
            new_password = data.get('new_password', 'password123')
            users_db[user_id]['password'] = new_password
            
            return jsonify({
                'ok': True,
                'message': f'Password reset for {username}',
                'vulnerability': 'Insecure password reset - no token verification'
            }), 200
    
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/auth/brute-force', methods=['POST'])
def red_brute_force():
    """VULNERABLE: No protection against brute force attacks"""
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    
    # VULNERABLE: No rate limiting, unlimited attempts allowed
    for user_id, user in users_db.items():
        if user['username'] == username and user['password'] == password:
            return jsonify({
                'ok': True,
                'message': 'Login successful',
                'vulnerability': 'No brute force protection'
            }), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401


# ============================================================================
# COMMAND INJECTION VULNERABILITIES (2 ENDPOINTS)
# ============================================================================

@app.route('/api/injection/command', methods=['POST'])
def red_command_injection():
    """VULNERABLE: OS command injection"""
    data = request.get_json() or {}
    filename = data.get('filename', 'test.txt')
    
    # VULNERABLE: Command injection via shell=True
    try:
        result = subprocess.run(f'ls -la {filename}', shell=True, capture_output=True, text=True, timeout=5)
        return jsonify({
            'ok': True,
            'output': result.stdout,
            'error': result.stderr,
            'vulnerability': 'Command injection via shell=True'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/injection/os-command', methods=['POST'])
def red_os_command():
    """VULNERABLE: OS command injection via ping"""
    data = request.get_json() or {}
    host = data.get('host', '127.0.0.1')
    
    # VULNERABLE: No input validation
    try:
        result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True, text=True, timeout=10)
        return jsonify({
            'ok': True,
            'output': result.stdout,
            'vulnerability': 'OS command injection'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# XXE VULNERABILITIES (2 ENDPOINTS)
# ============================================================================

@app.route('/api/injection/xml-xxe', methods=['POST'])
def red_xml_xxe():
    """VULNERABLE: XML External Entity (XXE) injection"""
    xml_data = request.data.decode('utf-8')
    
    try:
        # VULNERABLE: External entities enabled
        root = ET.fromstring(xml_data)
        
        return jsonify({
            'ok': True,
            'parsed': {
                'tag': root.tag,
                'text': root.text,
                'attrib': root.attrib
            },
            'vulnerability': 'XXE - External entities enabled'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/injection/xml-parse', methods=['POST'])
def red_xml_parse():
    """VULNERABLE: XML parsing with DTD enabled"""
    xml_data = request.data.decode('utf-8')
    
    try:
        # VULNERABLE: DTD processing enabled
        parser = ET.XMLParser()
        root = ET.fromstring(xml_data, parser)
        
        return jsonify({
            'ok': True,
            'data': ET.tostring(root, encoding='unicode'),
            'vulnerability': 'XXE via DTD processing'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# SSRF VULNERABILITIES (2 ENDPOINTS)
# ============================================================================

@app.route('/api/ssrf/fetch', methods=['POST'])
def red_ssrf():
    """VULNERABLE: Server-Side Request Forgery"""
    data = request.get_json() or {}
    url = data.get('url', '')
    
    # VULNERABLE: No URL validation, can access internal resources
    try:
        response = requests.get(url, timeout=5)
        return jsonify({
            'ok': True,
            'status_code': response.status_code,
            'content': response.text[:1000],  # Limit response size
            'vulnerability': 'SSRF - No URL validation'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ssrf/webhook', methods=['POST'])
def red_ssrf_webhook():
    """VULNERABLE: SSRF via webhook callback"""
    data = request.get_json() or {}
    callback_url = data.get('callback_url', '')
    
    # VULNERABLE: Accepts any callback URL including internal ones
    try:
        payload = {'event': 'test', 'data': 'sensitive data'}
        response = requests.post(callback_url, json=payload, timeout=5)
        
        return jsonify({
            'ok': True,
            'callback_status': response.status_code,
            'vulnerability': 'SSRF via webhook'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# OPEN REDIRECT VULNERABILITY
# ============================================================================

@app.route('/api/redirect/open', methods=['GET'])
def red_open_redirect():
    """VULNERABLE: Open redirect"""
    url = request.args.get('url', 'https://example.com')
    
    # VULNERABLE: Redirects to any URL without validation
    return jsonify({
        'redirect_to': url,
        'vulnerability': 'Open redirect - no URL validation',
        'message': 'In a real app, this would redirect the user'
    }), 302


# ============================================================================
# CSRF VULNERABILITY
# ============================================================================

@app.route('/api/csrf/transfer-funds', methods=['POST'])
def red_csrf_transfer():
    """VULNERABLE: No CSRF protection"""
    data = request.get_json() or {}
    amount = data.get('amount', 0)
    to_account = data.get('to_account', '')
    
    # VULNERABLE: No CSRF token validation
    return jsonify({
        'ok': True,
        'amount_transferred': amount,
        'to_account': to_account,
        'vulnerability': 'No CSRF protection'
    }), 200


# ============================================================================
# BUSINESS LOGIC VULNERABILITIES (4 ENDPOINTS)
# ============================================================================

@app.route('/api/business/race-condition', methods=['POST'])
def red_race_condition():
    """VULNERABLE: Race condition in balance update"""
    data = request.get_json() or {}
    user_id = data.get('user_id', 1)
    amount = data.get('amount', 10)
    
    # VULNERABLE: No transaction locking
    # In a real scenario, concurrent requests could cause issues
    if user_id not in users_db:
        users_db[user_id] = {'balance': 100}
    
    current_balance = users_db[user_id].get('balance', 100)
    
    # VULNERABLE: TOCTOU (Time of Check Time of Use)
    if current_balance >= amount:
        time.sleep(0.1)  # Simulate processing delay
        users_db[user_id]['balance'] = current_balance - amount
        
        return jsonify({
            'ok': True,
            'new_balance': users_db[user_id]['balance'],
            'vulnerability': 'Race condition - no locking'
        }), 200
    
    return jsonify({'error': 'Insufficient balance'}), 400


@app.route('/api/business/negative-amount', methods=['POST'])
def red_negative_amount():
    """VULNERABLE: Accepts negative amounts"""
    data = request.get_json() or {}
    amount = data.get('amount', 0)
    
    # VULNERABLE: No validation for negative amounts
    total = 100 + amount  # Could result in negative total
    
    return jsonify({
        'ok': True,
        'original': 100,
        'amount': amount,
        'total': total,
        'vulnerability': 'No validation for negative amounts'
    }), 200


@app.route('/api/business/coupon-stacking', methods=['POST'])
def red_coupon_stacking():
    """VULNERABLE: Multiple coupons can be applied"""
    data = request.get_json() or {}
    base_price = data.get('price', 100)
    coupons = data.get('coupons', [])
    
    # VULNERABLE: No check for duplicate coupon usage
    discount = 0
    for coupon in coupons:
        if coupon == 'SAVE10':
            discount += base_price * 0.1
        elif coupon == 'SAVE20':
            discount += base_price * 0.2
    
    final_price = base_price - discount
    
    return jsonify({
        'ok': True,
        'price': base_price,
        'discount': discount,
        'final': final_price,
        'vulnerability': 'Coupon stacking allowed'
    }), 200


@app.route('/api/business/payment-skip', methods=['POST'])
def red_payment_skip():
    """VULNERABLE: Can skip payment step"""
    data = request.get_json() or {}
    order_id = data.get('order_id', 1)
    
    # VULNERABLE: No validation of payment status
    order_status = 'completed'
    
    return jsonify({
        'ok': True,
        'order_id': order_id,
        'status': order_status,
        'vulnerability': 'Can skip payment step'
    }), 200


# ============================================================================
# FILE UPLOAD VULNERABILITIES (2 ENDPOINTS)
# ============================================================================

@app.route('/api/upload/unrestricted', methods=['POST'])
def red_file_upload():
    """VULNERABLE: Unrestricted file upload"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    # VULNERABLE: No file type validation, no size limits
    filename = file.filename
    # In production, this would save the file
    
    return jsonify({
        'ok': True,
        'filename': filename,
        'vulnerability': 'Unrestricted file upload - no validation'
    }), 200


@app.route('/api/upload/path-traversal', methods=['POST'])
def red_path_traversal():
    """VULNERABLE: Path traversal in file operations"""
    data = request.get_json() or {}
    filename = data.get('filename', 'file.txt')
    
    # VULNERABLE: No path validation
    filepath = f'/tmp/{filename}'  # Path traversal possible with ../
    
    return jsonify({
        'ok': True,
        'filepath': filepath,
        'vulnerability': 'Path traversal - no validation'
    }), 200


# ============================================================================
# DESERIALIZATION VULNERABILITY
# ============================================================================

@app.route('/api/integrity/insecure-deserialization', methods=['POST'])
def red_insecure_deserialization():
    """VULNERABLE: Insecure deserialization with pickle"""
    data = request.data
    
    try:
        # DANGEROUS: Deserializing untrusted data with pickle
        obj = pickle.loads(data)
        return jsonify({
            'ok': True,
            'deserialized': str(obj),
            'vulnerability': 'Insecure deserialization - RCE possible'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# INFORMATION DISCLOSURE VULNERABILITIES (4 ENDPOINTS)
# ============================================================================

@app.route('/api/info/error-verbose', methods=['GET'])
def red_error_verbose():
    """VULNERABLE: Verbose error messages"""
    trigger_error = request.args.get('error', 'false') == 'true'
    
    if trigger_error:
        # VULNERABLE: Detailed error exposure
        try:
            result = 1 / 0
        except Exception as e:
            import traceback
            return jsonify({
                'error': str(e),
                'traceback': traceback.format_exc(),  # DANGEROUS: Full stack trace
                'vulnerability': 'Verbose error messages'
            }), 500
    
    return jsonify({'ok': True}), 200


@app.route('/api/info/server-version', methods=['GET'])
def red_server_version():
    """VULNERABLE: Server version disclosure"""
    import sys
    import flask
    
    return jsonify({
        'ok': True,
        'python_version': sys.version,
        'flask_version': flask.__version__,
        'server': 'Flask Development Server',
        'vulnerability': 'Version disclosure'
    }), 200


@app.route('/api/info/debug-enabled', methods=['GET'])
def red_debug_enabled():
    """VULNERABLE: Debug mode enabled"""
    return jsonify({
        'ok': True,
        'debug_mode': app.config['DEBUG'],
        'secret_key': app.config['SECRET_KEY'],  # DANGEROUS: Leaking secrets
        'vulnerability': 'Debug mode enabled + secret disclosure'
    }), 200


@app.route('/api/info/user-enumeration', methods=['POST'])
def red_user_enumeration():
    """VULNERABLE: User enumeration via different responses"""
    data = request.get_json() or {}
    username = data.get('username', '')
    
    # VULNERABLE: Different responses for existing vs non-existing users
    user_exists = any(u['username'] == username for u in users_db.values())
    
    if user_exists:
        return jsonify({
            'error': 'Invalid password',  # Reveals user exists
            'user_exists': True
        }), 401
    else:
        return jsonify({
            'error': 'User not found',  # Reveals user doesn't exist
            'user_exists': False
        }), 404


# ============================================================================
# RESOURCE CONSUMPTION VULNERABILITIES (3 ENDPOINTS)
# ============================================================================

@app.route('/api/resource/unlimited-results', methods=['GET'])
def red_unlimited_results():
    """VULNERABLE: No pagination limits"""
    # VULNERABLE: Returns all records, could be millions
    all_users = list(users_db.values())
    
    return jsonify({
        'ok': True,
        'users': all_users,
        'count': len(all_users),
        'vulnerability': 'No pagination - returns all results'
    }), 200


@app.route('/api/resource/no-timeout', methods=['POST'])
def red_no_timeout():
    """VULNERABLE: No request timeout"""
    data = request.get_json() or {}
    sleep_time = data.get('sleep', 1)
    
    # VULNERABLE: No timeout, can cause resource exhaustion
    time.sleep(sleep_time)
    
    return jsonify({
        'ok': True,
        'slept_for': sleep_time,
        'vulnerability': 'No timeout limits'
    }), 200


@app.route('/api/resource/memory-intensive', methods=['POST'])
def red_memory_intensive():
    """VULNERABLE: No memory limits"""
    data = request.get_json() or {}
    size = data.get('size', 1000)
    
    # VULNERABLE: Can allocate unlimited memory
    large_list = ['x' * 1000] * size
    
    return jsonify({
        'ok': True,
        'allocated': len(large_list),
        'vulnerability': 'No memory limits'
    }), 200


# ============================================================================
# ADDITIONAL OWASP VULNERABILITIES
# ============================================================================

@app.route('/api/vulnerable-components', methods=['GET'])
def red_vulnerable_components():
    """VULNERABLE: Using outdated components with known CVEs"""
    return jsonify({
        'ok': True,
        'library': 'old-xml-parser',
        'version': '1.0.0',
        'cve': 'CVE-2021-12345',
        'risk': 'Critical - Remote Code Execution possible',
        'vulnerability': 'Vulnerable and outdated components'
    }), 200


@app.route('/api/undocumented-admin', methods=['GET'])
def red_undocumented_endpoint():
    """VULNERABLE: Undocumented endpoint exposing admin functions"""
    return jsonify({
        'ok': True,
        'admin_users': [u['username'] for u in users_db.values() if u.get('is_admin')],
        'api_version': '1.0-internal',
        'debug_mode': True,
        'vulnerability': 'Undocumented endpoint - improper inventory'
    }), 200


@app.route('/api/weak-jwt', methods=['POST'])
def red_weak_jwt():
    """VULNERABLE: Weak JWT implementation"""
    data = request.get_json() or {}
    username = data.get('username', 'user')
    
    # VULNERABLE: Predictable secret, no expiration
    token = hashlib.md5(f"{username}:secret123".encode()).hexdigest()
    
    return jsonify({
        'ok': True,
        'token': token,
        'vulnerability': 'Weak JWT - MD5 hash, predictable secret'
    }), 200


# ============================================================================
# HEALTH AND INFO ENDPOINTS
# ============================================================================

@app.route('/api/health', methods=['GET'])
def red_health():
    """Health check endpoint"""
    return jsonify({
        'ok': True,
        'status': 'running',
        'mode': 'red_team',
        'warning': 'These endpoints are intentionally vulnerable for educational purposes'
    }), 200


@app.route('/api/vulnerabilities', methods=['GET'])
def red_vulnerabilities_list():
    """List all vulnerabilities in this API"""
    vulnerabilities = {
        'sql_injection': {
            'count': 3,
            'endpoints': ['/api/injection/sqli/boolean', '/api/injection/sqli/time-based', '/api/injection/sqli/union']
        },
        'xss': {
            'count': 3,
            'endpoints': ['/api/xss/reflected', '/api/xss/stored', '/api/xss/dom']
        },
        'access_control': {
            'count': 4,
            'endpoints': ['/api/access/idor/<id>', '/api/access/privilege-escalation', '/api/access/bola/<id>', '/api/access/horizontal-privilege']
        },
        'authentication': {
            'count': 4,
            'endpoints': ['/api/auth/login', '/api/auth/register', '/api/auth/password-reset', '/api/auth/brute-force']
        },
        'command_injection': {
            'count': 2,
            'endpoints': ['/api/injection/command', '/api/injection/os-command']
        },
        'xxe': {
            'count': 2,
            'endpoints': ['/api/injection/xml-xxe', '/api/injection/xml-parse']
        },
        'ssrf': {
            'count': 2,
            'endpoints': ['/api/ssrf/fetch', '/api/ssrf/webhook']
        },
        'open_redirect': {
            'count': 1,
            'endpoints': ['/api/redirect/open']
        },
        'csrf': {
            'count': 1,
            'endpoints': ['/api/csrf/transfer-funds']
        },
        'business_logic': {
            'count': 4,
            'endpoints': ['/api/business/race-condition', '/api/business/negative-amount', '/api/business/coupon-stacking', '/api/business/payment-skip']
        },
        'file_upload': {
            'count': 2,
            'endpoints': ['/api/upload/unrestricted', '/api/upload/path-traversal']
        },
        'deserialization': {
            'count': 1,
            'endpoints': ['/api/integrity/insecure-deserialization']
        },
        'information_disclosure': {
            'count': 4,
            'endpoints': ['/api/info/error-verbose', '/api/info/server-version', '/api/info/debug-enabled', '/api/info/user-enumeration']
        },
        'resource_consumption': {
            'count': 3,
            'endpoints': ['/api/resource/unlimited-results', '/api/resource/no-timeout', '/api/resource/memory-intensive']
        },
        'additional': {
            'count': 3,
            'endpoints': ['/api/vulnerable-components', '/api/undocumented-admin', '/api/weak-jwt']
        }
    }
    
    total = sum(v['count'] for v in vulnerabilities.values())
    
    return jsonify({
        'ok': True,
        'total_vulnerabilities': total,
        'categories': len(vulnerabilities),
        'vulnerabilities': vulnerabilities,
        'warning': '⚠️ All endpoints are intentionally vulnerable for educational purposes only'
    }), 200


if __name__ == '__main__':
    # Development settings (intentionally insecure)
    app.config['DEBUG'] = True
    app.config['ENV'] = 'development'
    
    # Run on port 5000 (red team)
    print("=" * 70)
    print("🔴 AegisForge RED TEAM API Starting...")
    print("⚠️  WARNING: Intentionally vulnerable endpoints for educational use only")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5000, debug=True)
