"""
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

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aegisforge.db'
app.config['SECRET_KEY'] = 'aegisforge-dev-secret-2026'
app.config['JWT_SECRET_KEY'] = 'aegisforge-jwt-2026-secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

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
    return {
        'ok': True,
        'service': 'AegisForge',
        'version': '2.0',
        'vulnerabilities_count': 52,
        'endpoints_count': 30,
        'timestamp': datetime.utcnow().isoformat()
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
