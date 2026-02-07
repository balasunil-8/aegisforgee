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

# Register OWASP vulnerability modules
try:
    from owasp_integration import register_owasp_modules
    register_owasp_modules(app)
except ImportError:
    print("⚠️ OWASP modules not available (optional)")

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
AegisForge - Ultimate Security Learning Platform
Version 1.0.0
Master Offensive & Defensive Security
Built for professional penetration testers, blue-teamers and security researchers
"""

from flask import Flask, render_template_string, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import sqlite3
import os
import json
import time
import subprocess
import requests
from datetime import datetime, timedelta
import hashlib
import secrets
from functools import wraps
import logging

# AI Detector
from ai_detector import get_detector
from ctf_manager import list_challenges, generate_challenge, read_challenge

# Mode switching and defenses
from aegisforge_modes import (
    get_current_mode, toggle_mode, get_mode_info, 
    is_red_team_mode, is_blue_team_mode, SecurityMode
)
from defenses import (
    add_security_headers, check_rate_limit, get_waf, 
    validate_url, sanitize_sql_input, sanitize_xss_input
)

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aegisforge.db'
app.config['SECRET_KEY'] = 'aegisforge-dev-secret-2026'
app.config['JWT_SECRET_KEY'] = 'aegisforge-jwt-2026-secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SECURE'] = False  # Set True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_admin = db.Column(db.Boolean, default=False)
    api_key = db.Column(db.String(255), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_admin': self.is_admin
        }

class VulnerabilityLab(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    vuln_id = db.Column(db.String(50))
    completion_status = db.Column(db.String(20))  # 'started', 'exploited', 'defended'
    payload_used = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class APILog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    endpoint = db.Column(db.String(255))
    method = db.Column(db.String(10))
    status_code = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_attack = db.Column(db.Boolean, default=False)
    payload = db.Column(db.Text)

# ============================================================================
# MIDDLEWARE & DECORATORS
# ============================================================================

def log_attack(endpoint, payload, is_attack=True):
    """Log suspicious activity for monitoring"""
    try:
        log = APILog(
            endpoint=endpoint,
            method=request.method,
            status_code=200,
            is_attack=is_attack,
            payload=payload[:500] if payload else None
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Logging error: {e}")

def rate_limit_check():
    """Check rate limiting (currently disabled for testing)"""
    # TODO: Implement Redis-based rate limiting
    return True

# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register new user"""
    data = request.get_json()
    
    if User.query.filter_by(username=data.get('username')).first():
        return {'error': 'User already exists'}, 400
    
    user = User(
        username=data.get('username'),
        email=data.get('email'),
        password=data.get('password'),  # VULNERABLE: Not hashed!
        api_key=secrets.token_hex(32)
    )
    
    db.session.add(user)
    db.session.commit()
    
    return {'message': 'User registered', 'user_id': user.id}, 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    VULNERABLE: Broken Authentication
    - No rate limiting
    - Weak password validation
    - Default credentials accepted
    - SQL injection in username
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    log_attack('/api/auth/login', f"username={username}")
    
    # VULNERABLE: Default credentials
    if username == 'admin' and password == 'admin':
        return {'token': 'default-admin-token-123', 'user_id': 1}, 200
    
    # VULNERABLE: Direct SQL query (will be implemented in separate endpoint)
    user = User.query.filter_by(username=username).first()
    
    if user and user.password == password:  # VULNERABLE: Plaintext comparison
        token = create_access_token(identity=user.username)
        return {'token': token, 'user_id': user.id}, 200
    
    return {'error': 'Invalid credentials'}, 401

# ============================================================================
# INJECTION VULNERABILITIES
# ============================================================================

@app.route('/api/injection/sqli/boolean', methods=['GET'])
def sqli_boolean():
    """
    VULNERABLE: Boolean-Based SQL Injection
    Test: /api/injection/sqli/boolean?username=' OR '1'='1
    Expected: Returns all users if vulnerable
    """
    username = request.args.get('username', '')
    
    log_attack('/api/injection/sqli/boolean', f"username={username}")
    
    # VULNERABLE: Direct string concatenation
    try:
        query = f"SELECT * FROM user WHERE username = '{username}'"
        conn = sqlite3.connect('aegisforge.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query)
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return {
            'ok': True,
            'query': query,  # VULNERABLE: Exposed for teaching
            'results': results,
            'count': len(results)
        }, 200
    except Exception as e:
        return {'error': str(e), 'query': query}, 500

@app.route('/api/injection/sqli/time-based', methods=['GET'])
def sqli_time_based():
    """
    VULNERABLE: Time-Based Blind SQL Injection
    Test: /api/injection/sqli/time-based?id=1' AND SLEEP(5)--
    Expected: Response delayed if vulnerable
    """
    user_id = request.args.get('id', '1')
    
    log_attack('/api/injection/sqli/time-based', f"id={user_id}")
    
    # VULNERABLE: Time-based injection
    if 'SLEEP' in user_id.upper():
        time.sleep(5)  # Time-based response
        return {'ok': True, 'delayed': True}, 200
    
    return {'ok': True, 'user_id': user_id}, 200

@app.route('/api/injection/sqli/union', methods=['GET'])
def sqli_union():
    """
    VULNERABLE: UNION-Based SQL Injection
    Test: /api/injection/sqli/union?search=' UNION SELECT CONCAT(username,':',password) FROM user--
    Expected: Returns usernames and passwords
    """
    search = request.args.get('search', '')
    
    log_attack('/api/injection/sqli/union', f"search={search}")
    
    # VULNERABLE: UNION injection check
    if 'UNION' in search.upper():
        # Return sensitive data as proof of concept
        return {
            'ok': True,
            'union_detected': True,
            'sensitive_data': [
                {'username': 'admin', 'password': 'admin123'},
                {'username': 'user', 'password': 'pass456'}
            ]
        }, 200
    
    return {'ok': True, 'message': 'No results'}, 200

@app.route('/api/injection/command', methods=['POST'])
def command_injection():
    """
    VULNERABLE: Command Injection
    Test: {"cmd": "id; whoami"}
    Expected: Executes system command
    """
    data = request.get_json()
    filename = data.get('filename', 'test')
    
    log_attack('/api/injection/command', f"filename={filename}")
    
    # VULNERABLE: Unsafe command execution
    try:
        # DANGEROUS: This executes arbitrary commands
        cmd = f"ls -la {filename}"
        result = subprocess.check_output(cmd, shell=True, text=True)
        return {'ok': True, 'output': result}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/api/injection/xml-xxe', methods=['POST'])
def xxe_injection():
    """
    VULNERABLE: XML External Entity (XXE) Injection
    Test: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    Expected: Returns file contents if vulnerable
    """
    xml_data = request.data.decode('utf-8')
    
    log_attack('/api/injection/xml-xxe', xml_data[:100])
    
    # VULNERABLE: Parse XML without disabling external entities
    try:
        import xml.etree.ElementTree as ET
        # DANGEROUS: No XXE protection
        root = ET.fromstring(xml_data)
        return {'ok': True, 'parsed': True}, 200
    except Exception as e:
        return {'error': str(e)}, 500

# ============================================================================
# XSS VULNERABILITIES
# ============================================================================

@app.route('/api/xss/reflected', methods=['GET'])
def xss_reflected():
    """
    VULNERABLE: Reflected XSS
    Test: /api/xss/reflected?message=<img src=x onerror=alert(1)>
    Expected: Returns unescaped HTML
    """
    message = request.args.get('message', '')
    
    log_attack('/api/xss/reflected', message)
    
    # VULNERABLE: Unescaped output
    html = f"""
    <html>
    <body>
    <h1>Message:</h1>
    <p>{message}</p>
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
@app.route('/api/xss/stored', methods=['POST', 'GET'])
def xss_stored():
    """
    VULNERABLE: Stored XSS
    Test: POST with comment containing script tag
    Expected: Script executes on retrieval
    """
    if request.method == 'POST':
        data = request.get_json()
        comment = data.get('comment', '')
        # VULNERABLE: Comment stored without sanitization
        return {'ok': True, 'stored': comment}, 201
    else:
        # Return stored comments
        return {
            'ok': True,
            'comments': [
                {'id': 1, 'text': '<img src=x onerror="alert(\'Stored XSS\')">'},
                {'id': 2, 'text': '<script>alert("Stored XSS")</script>'}
            ]
        }, 200

@app.route('/api/xss/dom', methods=['GET'])
def xss_dom():
    """
    VULNERABLE: DOM-Based XSS
    Test: /api/xss/dom?userInput=<script>alert(1)</script>
    """
    user_input = request.args.get('userInput', '')
    
    html = f"""
    <html>
    <script>
    var userInput = '{user_input}';
    document.getElementById('output').innerHTML = userInput;
    </script>
    <div id='output'></div>
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
# ============================================================================
# ACCESS CONTROL VULNERABILITIES
# ============================================================================

@app.route('/api/access/idor/<int:user_id>', methods=['GET'])
def idor_access(user_id):
    """
    VULNERABLE: Insecure Direct Object Reference (IDOR)
    Test: /api/access/idor/2 (access another user's data)
    Expected: Returns data without ownership validation
    """
    log_attack(f'/api/access/idor/{user_id}', '')
    
    # VULNERABLE: No authorization check
    users = {
        1: {'id': 1, 'username': 'admin', 'email': 'admin@test.com', 'ssn': '123-45-6789', 'salary': 150000},
        2: {'id': 2, 'username': 'user1', 'email': 'user1@test.com', 'ssn': '987-65-4321', 'salary': 75000},
        3: {'id': 3, 'username': 'user2', 'email': 'user2@test.com', 'ssn': '555-55-5555', 'salary': 65000}
    }
    
    if user_id in users:
        return users[user_id], 200
    
    return {'error': 'User not found'}, 404

@app.route('/api/access/privilege-escalation', methods=['PUT'])
def privilege_escalation():
    """
    VULNERABLE: Privilege Escalation
    Test: PUT {"is_admin": true, "role": "admin"}
    Expected: Attacker can escalate their own privileges
    """
    data = request.get_json()
    
    # VULNERABLE: No authorization, allows mass assignment
    user = {
        'id': 1,
        'username': 'attacker',
        'is_admin': data.get('is_admin', False),  # VULNERABLE: Direct setting
        'role': data.get('role', 'user'),  # VULNERABLE: Mass assignment
        'permissions': data.get('permissions', [])
    }
    
    log_attack('/api/access/privilege-escalation', str(data))
    
    return {'ok': True, 'user': user}, 200

# ============================================================================
# AUTHENTICATION FLAWS
# ============================================================================

@app.route('/api/auth/weak-password', methods=['POST'])
def weak_password():
    """
    VULNERABLE: Weak Password Policy
    Test: POST {"username": "test", "password": "1"}
    Expected: Accepts weak password
    """
    data = request.get_json()
    password = data.get('password', '')
    
    # VULNERABLE: No password complexity requirements
    if len(password) >= 1:  # Only 1 character required!
        return {'ok': True, 'message': 'Password accepted'}, 201
    
    return {'error': 'Password too short'}, 400

@app.route('/api/auth/brute-force', methods=['POST'])
def brute_force():
    """
    VULNERABLE: No Rate Limiting / Brute Force Protection
    Test: Send 100 requests with different passwords
    Expected: All attempts processed without delays
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # VULNERABLE: No rate limiting, accepts all attempts
    log_attack('/api/auth/brute-force', f"{username}:{password}")
    
    if username == 'admin' and len(password) > 0:
        return {'ok': True, 'message': 'Login attempt processed'}, 200
    
    return {'error': 'Invalid'}, 401

# ============================================================================
# MISCONFIGURATION VULNERABILITIES  
# ============================================================================

@app.route('/api/config/exposed', methods=['GET'])
def exposed_config():
    """
    VULNERABLE: Security Misconfiguration - Exposed Config
    Test: GET /api/config/exposed
    Expected: Returns sensitive configuration
    """
    log_attack('/api/config/exposed', '')
    
    # VULNERABLE: Expose sensitive configuration
    return {
        'ok': True,
        'debug': True,  # DEBUG MODE!!!
        'database': {
            'host': 'localhost',
            'port': 5432,
            'user': 'admin',
            'password': 'database123',  # VULNERABLE: Exposed password
            'database': 'aegisforge'
        },
        'api_keys': {
            'stripe': 'sk_test_abcd1234',  # VULNERABLE: API key exposed
            'aws': 'AKIA1234567890ABCDEF'
        },
        'jwt_secret': app.config['JWT_SECRET_KEY'],  # VULNERABLE: Secret exposed
        'admin_email': 'admin@aegisforge.local',
        'version': '2.0-Enterprise'
    }, 200

@app.route('/api/admin/debug', methods=['GET'])
def admin_debug():
    """
    VULNERABLE: Debug endpoint accessible to all
    Test: GET /api/admin/debug
    Expected: Returns debug information
    """
    log_attack('/api/admin/debug', '')
    
    # VULNERABLE: Debug endpoint with no auth check
    return {
        'ok': True,
        'environment': os.environ.copy(),  # DANGEROUS
        'config': app.config.copy(),  # DANGEROUS
        'database_stats': {
            'users': User.query.count(),
            'logs': APILog.query.count()
        }
    }, 200

# ============================================================================
# SSRF & OPEN REDIRECT
# ============================================================================

@app.route('/api/ssrf/fetch', methods=['POST'])
def ssrf_fetch():
    """
    VULNERABLE: Server-Side Request Forgery (SSRF)
    Test: POST {"url": "http://169.254.169.254/latest/meta-data/"}
    Expected: Fetches internal resources
    """
    data = request.get_json()
    url = data.get('url', '')
    
    log_attack('/api/ssrf/fetch', url)
    
    # VULNERABLE: Fetch arbitrary URLs
    try:
        response = requests.get(url, timeout=5)
        return {
            'ok': True,
            'url': url,
            'status': response.status_code,
            'content': response.text[:500]
        }, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/api/redirect/open', methods=['GET'])
def open_redirect():
    """
    VULNERABLE: Open Redirect
    Test: GET /api/redirect/open?url=http://attacker.com
    Expected: Redirects to attacker site
    """
    redirect_url = request.args.get('url', '')
    
    log_attack('/api/redirect/open', redirect_url)
    
    # VULNERABLE: No whitelist validation
    return {
        'ok': True,
        'redirect': redirect_url,
        'message': 'Redirecting to ' + redirect_url
    }, 200

# ============================================================================
# BUSINESS LOGIC FLAWS
# ============================================================================

@app.route('/api/business/race-condition', methods=['POST'])
def race_condition():
    """
    VULNERABLE: Race Condition / TOCTOU
    Test: Send concurrent requests to process same transaction twice
    Expected: Both requests process successfully
    """
    data = request.get_json()
    transaction_id = data.get('transaction_id', '')
    amount = data.get('amount', 0)
    
    log_attack('/api/business/race-condition', f"tx_id={transaction_id}")
    
    # VULNERABLE: No atomic transaction handling
    # Two concurrent requests can both succeed for same transaction
    return {
        'ok': True,
        'transaction_id': transaction_id,
        'amount': amount,
        'status': 'processed'  # VULNERABLE: No idempotency check
    }, 200

@app.route('/api/business/negative-amount', methods=['POST'])
def negative_amount():
    """
    VULNERABLE: Business Logic Flaw - Negative Amount
    Test: POST {"amount": -100}
    Expected: Processes negative withdrawal as deposit
    """
    data = request.get_json()
    amount = data.get('amount', 0)
    
    log_attack('/api/business/negative-amount', f"amount={amount}")
    
    # VULNERABLE: No sign validation
    balance = 1000
    balance += amount  # VULNERABLE: Should validate and reject negative amounts
    
    return {
        'ok': True,
        'amount': amount,
        'new_balance': balance,
        'message': 'Transaction processed'
    }, 200

# ============================================================================
# INFORMATION DISCLOSURE
# ============================================================================

@app.route('/api/error/verbose', methods=['GET'])
def verbose_error():
    """
    VULNERABLE: Verbose Error Messages
    Test: GET /api/error/verbose?file=nonexistent
    Expected: Reveals system information
    """
    filename = request.args.get('file', '')
    
    try:
        with open(filename, 'r') as f:
            return f.read(), 200
    except Exception as e:
        # VULNERABLE: Detailed error messages
        return {
            'ok': False,
            'error': str(e),
            'error_type': type(e).__name__,
            'traceback': 'Full stack trace would appear here'  # VULNERABLE
        }, 500

@app.route('/api/info/path-traversal', methods=['GET'])
def path_traversal():
    """
    VULNERABLE: Path Traversal
    Test: GET /api/info/path-traversal?path=../../../../etc/passwd
    Expected: Returns system files
    """
    filepath = request.args.get('path', '')
    
    log_attack('/api/info/path-traversal', filepath)
    
    # VULNERABLE: No path validation
    try:
        with open(filepath, 'r') as f:
            return {'ok': True, 'content': f.read()}, 200
    except:
        return {'error': 'File not found'}, 404

# ============================================================================
# SUPPORTING ENDPOINTS
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    mode_info = get_mode_info()
    return {
        'ok': True,
        'service': 'AegisForge',
        'version': '1.0.0',
        'tagline': 'Master Offensive & Defensive Security',
        'mode': mode_info['mode'],
        'mode_name': mode_info['name'],
        'vulnerabilities_count': 52,
        'endpoints_count': 30,
        'timestamp': datetime.utcnow().isoformat()
    }, 200


@app.route('/api/mode/status', methods=['GET'])
def mode_status():
    """Get current security mode status"""
    mode_info = get_mode_info()
    return {
        'ok': True,
        'current_mode': mode_info
    }, 200


@app.route('/api/mode/toggle', methods=['POST'])
def mode_toggle():
    """Toggle between Red Team and Blue Team modes"""
    try:
        new_mode = toggle_mode()
        mode_info = get_mode_info()
        
        return {
            'ok': True,
            'message': f'Switched to {mode_info["name"]} mode',
            'previous_mode': 'red' if new_mode == SecurityMode.BLUE_TEAM else 'blue',
            'current_mode': mode_info
        }, 200
    except Exception as e:
        return {'ok': False, 'error': str(e)}, 500


@app.route('/api/mode/set', methods=['POST'])
def mode_set():
    """Set specific security mode"""
    data = request.get_json() or {}
    mode_str = data.get('mode', '').lower()
    
    if mode_str not in ['red', 'blue']:
        return {'ok': False, 'error': 'Mode must be "red" or "blue"'}, 400
    
    try:
        from aegisforge_modes import set_mode
        mode = SecurityMode.RED_TEAM if mode_str == 'red' else SecurityMode.BLUE_TEAM
        set_mode(mode)
        
        mode_info = get_mode_info()
        return {
            'ok': True,
            'message': f'Mode set to {mode_info["name"]}',
            'current_mode': mode_info
        }, 200
    except Exception as e:
        return {'ok': False, 'error': str(e)}, 500


@app.route('/api/defenses/info', methods=['GET'])
def defenses_info():
    """Get information about available security defenses"""
    from defenses import get_security_headers_info
    waf = get_waf()
    
    return {
        'ok': True,
        'defenses': {
            'input_validation': {
                'available': True,
                'types': ['SQL injection', 'XSS', 'Command injection', 'Path traversal']
            },
            'security_headers': get_security_headers_info(),
            'rate_limiting': {
                'available': True,
                'default_limit': '100 requests per 60 seconds',
                'strict_limit': '10 requests per 60 seconds (for auth endpoints)'
            },
            'waf_rules': {
                'available': True,
                'rule_count': sum(len(rules) for rules in waf.rules.values()),
                'categories': list(waf.rules.keys())
            }
        }
    }, 200


@app.route('/api/ai/detect', methods=['POST'])
def ai_detect():
    """
    AI-powered detection endpoint.
    Request JSON: { "text": "payload or input to classify" }
    Returns JSON with label, attack_prob, model_proba (if available), heuristic
    """
    data = request.get_json() or {}
    text = data.get('text', '')
    if not text:
        return {'error': 'Missing "text" in JSON body'}, 400

    detector = get_detector()
    result = detector.predict_label(text)

    # Log as attack if probability high
    try:
        prob = float(result.get('attack_prob', 0.0))
    except Exception:
        prob = 0.0

    log_attack('/api/ai/detect', text[:500], is_attack=(prob >= 0.5))

    return {'ok': True, 'analysis': result}, 200


@app.route('/api/ai/debug', methods=['POST'])
def ai_debug():
    """
    Debug endpoint: returns raw detector output and persists a copy to `instance/ai_debug_last.json` for inspection.
    Useful for automated tests that read filesystem artifacts.
    """
    data = request.get_json() or {}
    text = data.get('text', '')
    if not text:
        return {'error': 'Missing "text" in JSON body'}, 400

    detector = get_detector()
    result = detector.predict_label(text)

    # persist last debug output
    try:
        os.makedirs('instance', exist_ok=True)
        with open(os.path.join('instance', 'ai_debug_last.json'), 'w', encoding='utf-8') as fh:
            json.dump({'text': text, 'result': result}, fh, indent=2)
    except Exception as e:
        logger.warning(f"Failed to write debug file: {e}")

    return {'ok': True, 'analysis': result}, 200

@app.route('/api/vulnerabilities/list', methods=['GET'])
def vulnerabilities_list():
    """List all vulnerabilities in the lab"""
    with open('PENTESTLAB_VULNERABILITIES.json', 'r') as f:
        data = json.load(f)
    return {
        'ok': True,
        'total_vulnerabilities': data['metadata']['total_vulnerabilities'],
        'standards': data['metadata']['standards'],
        'vulnerabilities': [v.get('title') for v in data['vulnerabilities'][:10]]
    }, 200


@app.route('/api/ctf/list', methods=['GET'])
def ctf_list():
    """List generated CTF challenges."""
    try:
        items = list_challenges()
        return {'ok': True, 'challenges': items}, 200
    except Exception as e:
        return {'ok': False, 'error': str(e)}, 500


@app.route('/api/ctf/generate', methods=['POST'])
def ctf_generate():
    """Generate a new CTF challenge. JSON: {"kind":"crypto","title":"SmallE 101"}
    Returns new challenge metadata.
    """
    data = request.get_json() or {}
    kind = data.get('kind')
    title = data.get('title')
    if not kind or not title:
        return {'error': 'Missing kind or title'}, 400
    try:
        meta = generate_challenge(kind, title)
        return {'ok': True, 'challenge': meta}, 201
    except Exception as e:
        return {'ok': False, 'error': str(e)}, 500


@app.route('/api/ctf/get/<cid>', methods=['GET'])
def ctf_get(cid):
    """Retrieve challenge metadata by id."""
    try:
        meta = read_challenge(cid)
        if not meta:
            return {'error': 'Not found'}, 404
        return {'ok': True, 'challenge': meta}, 200
    except Exception as e:
        return {'ok': False, 'error': str(e)}, 500


@app.route('/api/ctf/challenges/<challenge_name>', methods=['GET'])
def ctf_challenge_get(challenge_name):
    """
    Get a specific AegisForge CTF challenge
    Available challenges: area64, smalle, hidden_layers, paper_script, synthetic_stacks
    """
    challenge_map = {
        'area64': 'ctf_challenges.area64.challenge',
        'smalle': 'ctf_challenges.smalle.challenge',
        'hidden_layers': 'ctf_challenges.hidden_layers.challenge',
        'paper_script': 'ctf_challenges.paper_script.challenge',
        'synthetic_stacks': 'ctf_challenges.synthetic_stacks.challenge'
    }
    
    if challenge_name not in challenge_map:
        return {
            'ok': False,
            'error': 'Challenge not found',
            'available_challenges': list(challenge_map.keys())
        }, 404
    
    try:
        # Dynamically import the challenge module
        import importlib
        module = importlib.import_module(challenge_map[challenge_name])
        
        # Generate challenge for the user
        user_id = request.args.get('user_id', 'anonymous')
        challenge_data = module.generate_challenge(user_id)
        
        # Don't expose the flag in the response
        response_data = {
            'ok': True,
            'challenge': {
                'id': challenge_data['challenge_id'],
                'name': challenge_data['name'],
                'category': challenge_data['category'],
                'difficulty': challenge_data['difficulty'],
                'points': challenge_data['points'],
                'description': challenge_data['description'],
                'artifacts': challenge_data['artifacts'],
                'hints': challenge_data.get('hints', [])
            }
        }
        
        # Store the flag in session for verification later
        from flask import session
        if 'ctf_flags' not in session:
            session['ctf_flags'] = {}
        session['ctf_flags'][challenge_name] = challenge_data['flag']
        session.modified = True
        
        return response_data, 200
        
    except Exception as e:
        logger.error(f"Error loading challenge {challenge_name}: {e}")
        return {'ok': False, 'error': str(e)}, 500


@app.route('/api/ctf/challenges/<challenge_name>/verify', methods=['POST'])
def ctf_challenge_verify(challenge_name):
    """
    Verify a submitted flag for a CTF challenge
    Request: {"flag": "HQX{...}"}
    """
    data = request.get_json() or {}
    submitted_flag = data.get('flag', '').strip()
    
    if not submitted_flag:
        return {'ok': False, 'error': 'No flag provided'}, 400
    
    # Get the correct flag from session
    from flask import session
    correct_flag = session.get('ctf_flags', {}).get(challenge_name)
    
    if not correct_flag:
        return {
            'ok': False,
            'error': 'Challenge not started. Get the challenge first.',
            'hint': f'GET /api/ctf/challenges/{challenge_name}'
        }, 400
    
    # Verify the flag
    is_correct = submitted_flag == correct_flag
    
    if is_correct:
        return {
            'ok': True,
            'correct': True,
            'message': f'🎉 Congratulations! Flag accepted for {challenge_name}!',
            'challenge': challenge_name
        }, 200
    else:
        return {
            'ok': True,
            'correct': False,
            'message': 'Incorrect flag. Keep trying!',
            'challenge': challenge_name
        }, 200


@app.route('/api/ctf/challenges/<challenge_name>/hint', methods=['POST'])
def ctf_challenge_hint(challenge_name):
    """
    Get a hint for a CTF challenge
    Request: {"hint_index": 0}  # 0-based index
    """
    data = request.get_json() or {}
    hint_index = data.get('hint_index', 0)
    
    challenge_map = {
        'area64': 'ctf_challenges.area64.challenge',
        'smalle': 'ctf_challenges.smalle.challenge',
        'hidden_layers': 'ctf_challenges.hidden_layers.challenge',
        'paper_script': 'ctf_challenges.paper_script.challenge',
        'synthetic_stacks': 'ctf_challenges.synthetic_stacks.challenge'
    }
    
    if challenge_name not in challenge_map:
        return {'ok': False, 'error': 'Challenge not found'}, 404
    
    try:
        import importlib
        module = importlib.import_module(challenge_map[challenge_name])
        challenge_data = module.generate_challenge('temp')
        hints = challenge_data.get('hints', [])
        
        if hint_index < 0 or hint_index >= len(hints):
            return {'ok': False, 'error': 'Invalid hint index'}, 400
        
        hint = hints[hint_index]
        return {
            'ok': True,
            'hint': hint,
            'hint_index': hint_index,
            'total_hints': len(hints)
        }, 200
        
    except Exception as e:
        logger.error(f"Error getting hint for {challenge_name}: {e}")
        return {'ok': False, 'error': str(e)}, 500


@app.route('/api/testing-guide', methods=['GET'])
def testing_guide():
    """Get testing guide for a specific vulnerability"""
    vuln_id = request.args.get('vuln_id')
    
    with open('AEGISFORGE_VULNERABILITIES.json', 'r') as f:
        data = json.load(f)
    
    for vuln in data['vulnerabilities']:
        if vuln.get('id') == vuln_id:
            return {
                'ok': True,
                'vulnerability': {
                    'title': vuln.get('title'),
                    'description': vuln.get('description'),
                    'payloads': vuln.get('payloads'),
                    'tool_commands': vuln.get('tool_specific_commands'),
                    'testing_methodology': vuln.get('testing_methodology')
                }
            }, 200
    
    return {'error': 'Vulnerability not found'}, 404

@app.route('/')
def dashboard():
    """Main dashboard"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>AegisForge - Master Offensive & Defensive Security</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #fff; }
            .container { max-width: 1200px; margin: 0 auto; }
            h1 { color: #ff0000; }
            .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
            .stat { background: #2a2a2a; padding: 20px; border-radius: 8px; text-align: center; }
            .stat h3 { margin: 0; color: #4CAF50; }
            .stat p { margin: 10px 0 0 0; }
            .endpoints-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin: 20px 0; }
            .endpoint { background: #2a2a2a; padding: 15px; border-left: 4px solid #ff0000; border-radius: 4px; }
            .endpoint h3 { margin: 0; color: #ff9800; }
            .endpoint code { background: #1a1a1a; padding: 10px; display: block; margin: 10px 0; }
            .severity { display: inline-block; padding: 5px 10px; border-radius: 4px; }
            .critical { background: #ff0000; color: white; }
            .high { background: #ff9800; color: white; }
            .medium { background: #2196F3; color: white; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ AegisForge v1.0.0</h1>
            <p style="color: #666; margin-top: 0;">Master Offensive & Defensive Security</p>
            <p>Industry-Grade API Security & Web Application Testing Platform</p>
            
            <div class="stats">
                <div class="stat">
                    <h3>52</h3>
                    <p>Vulnerabilities</p>
                </div>
                <div class="stat">
                    <h3>30+</h3>
                    <p>Endpoints</p>
                </div>
                <div class="stat">
                    <h3>5</h3>
                    <p>Testing Tools</p>
                </div>
                <div class="stat">
                    <h3>100%</h3>
                    <p>Coverage</p>
                </div>
            </div>
            
            <h2>💡 Quick Start</h2>
            <div class="endpoints-grid">
                <div class="endpoint">
                    <h3>SQL Injection</h3>
                    <span class="severity critical">CRITICAL</span>
                    <code>GET /api/injection/sqli/boolean?username=' OR '1'='1</code>
                </div>
                <div class="endpoint">
                    <h3>XSS (Reflected)</h3>
                    <span class="severity critical">CRITICAL</span>
                    <code>GET /api/xss/reflected?message=&lt;img src=x onerror="alert(1)"&gt;</code>
                </div>
                <div class="endpoint">
                    <h3>IDOR</h3>
                    <span class="severity critical">CRITICAL</span>
                    <code>GET /api/access/idor/2</code>
                </div>
                <div class="endpoint">
                    <h3>Exposed Config</h3>
                    <span class="severity critical">CRITICAL</span>
                    <code>GET /api/config/exposed</code>
                </div>
            </div>
            
            <h2>📚 Get Started</h2>
            <ul>
                <li><a href="/api/vulnerabilities/list" style="color: #4CAF50;">View all vulnerabilities</a></li>
                <li><a href="/api/health" style="color: #4CAF50;">Health check</a></li>
                <li><a href="/api/testing-guide?vuln_id=WEB-2021-A01" style="color: #4CAF50;">SQL Injection guide</a></li>
            </ul>
            
            <h2>⚠️ DISCLAIMER</h2>
            <p>This is an intentionally vulnerable application for educational and authorized testing ONLY.</p>
            <p>Unauthorized access to computer systems is illegal.</p>
        </div>
    </body>
    </html>
    '''

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return {'error': 'Endpoint not found', 'message': 'Check /api/health for available endpoints'}, 404

@app.errorhandler(500)
def server_error(e):
    # VULNERABLE: Detailed error exposure
    return {'error': 'Server error', 'details': str(e)}, 500

# ============================================================================
# APPLICATION STARTUP
# ============================================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create default users for testing
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@aegisforge.local',
                password='admin123',  # VULNERABLE: Plaintext
                role='admin',
                is_admin=True,
                api_key=secrets.token_hex(32)
            )
            db.session.add(admin)
            db.session.commit()
        
        logger.info("AegisForge platform initialized")
        app.run(debug=True, host='0.0.0.0', port=5000)
