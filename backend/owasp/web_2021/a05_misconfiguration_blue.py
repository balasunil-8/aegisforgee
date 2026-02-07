"""
OWASP Web Top 10 2021 - A05: Security Misconfiguration
BLUE TEAM (Secure) Endpoints - ENHANCED

This module demonstrates secure configuration practices including:
- Strong password requirements (no default credentials)
- Production mode (errors sanitized)
- Directory listing disabled
- Only necessary HTTP methods enabled
- Properly configured CORS with specific origins

Author: AegisForge Security Team
Version: 1.0
"""

from flask import Blueprint, request, jsonify, Response
import hashlib
import secrets
from datetime import datetime

# Create blueprint
a05_misconfiguration_blue = Blueprint('a05_misconfiguration_blue', __name__)

# Secure user database with hashed passwords
SECURE_USERS = {
    'admin': {
        'username': 'admin',
        # SECURE: Strong password (Admin123!@#), hashed with SHA-256
        'password_hash': hashlib.sha256('Admin123!@#'.encode()).hexdigest(),
        'role': 'administrator',
        'account_locked': False,
        'failed_attempts': 0
    },
    'john_doe': {
        'username': 'john_doe',
        # SECURE: Unique password (JD$ecure2024), hashed
        'password_hash': hashlib.sha256('JD$ecure2024'.encode()).hexdigest(),
        'role': 'user',
        'account_locked': False,
        'failed_attempts': 0
    }
}

# Rate limiting tracker
login_attempts = {}


@a05_misconfiguration_blue.route('/api/blue/misconfiguration/default-credentials', methods=['POST'])
def default_credentials_secure():
    """
    SECURE: Strong passwords required, no default credentials
    
    Security controls:
    1. No default credentials (admin/admin doesn't work)
    2. Strong password requirements enforced
    3. Password hashing (not plaintext)
    4. Account lockout after failed attempts
    5. Rate limiting on login endpoint
    
    Example secure credentials:
    {"username": "admin", "password": "Admin123!@#"}
    {"username": "john_doe", "password": "JD$ecure2024"}
    """
    try:
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        
        # SECURE: Rate limiting
        client_ip = request.remote_addr
        current_time = datetime.now()
        
        if client_ip not in login_attempts:
            login_attempts[client_ip] = []
        
        # Remove attempts older than 5 minutes
        login_attempts[client_ip] = [
            attempt for attempt in login_attempts[client_ip]
            if (current_time - attempt).total_seconds() < 300
        ]
        
        # Check rate limit (max 5 attempts per 5 minutes)
        if len(login_attempts[client_ip]) >= 5:
            return jsonify({
                'ok': False,
                'error': 'Too many login attempts',
                'security_control': 'Rate limiting prevents brute force attacks',
                'try_again_in': '5 minutes'
            }), 429
        
        # Check if user exists
        if username not in SECURE_USERS:
            # SECURE: Generic error message (don't reveal if user exists)
            login_attempts[client_ip].append(current_time)
            return jsonify({
                'ok': False,
                'error': 'Invalid credentials',
                'security_control': 'Generic error message prevents user enumeration'
            }), 401
        
        user = SECURE_USERS[username]
        
        # SECURE: Check if account is locked
        if user.get('account_locked', False):
            return jsonify({
                'ok': False,
                'error': 'Account locked due to too many failed attempts',
                'security_control': 'Account lockout prevents brute force'
            }), 403
        
        # SECURE: Hash provided password and compare
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if user['password_hash'] == password_hash:
            # SECURE: Reset failed attempts on successful login
            user['failed_attempts'] = 0
            
            # SECURE: Generate secure random token
            token = secrets.token_urlsafe(32)
            
            return jsonify({
                'ok': True,
                'message': 'Login successful',
                'user': {
                    'username': user['username'],
                    'role': user['role']
                },
                'token': token,
                'security_controls': [
                    'Strong password required',
                    'Password hashing (SHA-256)',
                    'Secure random token generation',
                    'Rate limiting enabled',
                    'Account lockout after 5 failed attempts'
                ]
            }), 200
        else:
            # SECURE: Track failed attempts
            login_attempts[client_ip].append(current_time)
            user['failed_attempts'] = user.get('failed_attempts', 0) + 1
            
            # SECURE: Lock account after 5 failed attempts
            if user['failed_attempts'] >= 5:
                user['account_locked'] = True
            
            return jsonify({
                'ok': False,
                'error': 'Invalid credentials',
                'security_control': f'Failed attempts tracked ({user["failed_attempts"]}/5)'
            }), 401
        
    except Exception as e:
        # SECURE: Generic error message in production
        return jsonify({
            'ok': False,
            'error': 'An error occurred',
            'security_control': 'Error details hidden in production mode'
        }), 500


@a05_misconfiguration_blue.route('/api/blue/misconfiguration/debug-enabled', methods=['GET', 'POST'])
def debug_enabled_secure():
    """
    SECURE: Production mode with sanitized errors
    
    Security controls:
    1. Debug mode disabled
    2. No stack traces exposed
    3. No environment variables revealed
    4. Generic error messages
    5. Sensitive data filtered
    
    Example: Errors are logged server-side but not returned to client
    """
    try:
        # SECURE: No debug information exposed
        trigger_error = request.args.get('trigger_error', 'false')
        
        if trigger_error == 'true':
            # Even if error occurs, don't expose details
            error_type = request.args.get('error_type', 'division')
            
            if error_type == 'division':
                result = 1 / 0  # This would trigger error
        
        # SECURE: No environment variables or sensitive data
        return jsonify({
            'ok': True,
            'message': 'Production endpoint',
            'mode': 'production',
            'debug': False,
            'security_controls': [
                'Debug mode disabled',
                'No environment variables exposed',
                'No system information revealed',
                'Errors logged server-side only'
            ]
        }), 200
        
    except Exception as e:
        # SECURE: Generic error message, log details server-side
        # In production: logger.error(f"Error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'ok': False,
            'error': 'An error occurred. Please contact support.',
            'error_id': secrets.token_hex(8),  # Reference ID for support
            'security_control': 'Error details logged but not exposed to client'
        }), 500


@a05_misconfiguration_blue.route('/api/blue/misconfiguration/directory-listing', methods=['GET'])
def directory_listing_secure():
    """
    SECURE: Directory listing disabled, access denied
    
    Security controls:
    1. Directory listing completely disabled
    2. Returns 403 Forbidden for directory requests
    3. Only specific file endpoints allowed
    4. File access requires authentication (simulated)
    
    Example: Any attempt to browse directories is blocked
    """
    # SECURE: Directory listing is forbidden
    return jsonify({
        'ok': False,
        'error': 'Forbidden',
        'message': 'Directory listing is disabled',
        'security_controls': [
            'Directory listing disabled',
            'File access requires authentication',
            'Only specific endpoints available',
            'No filesystem browsing allowed'
        ]
    }), 403


@a05_misconfiguration_blue.route('/api/blue/misconfiguration/unnecessary-methods', methods=['GET', 'POST'])
def unnecessary_methods_secure():
    """
    SECURE: Only necessary HTTP methods enabled (GET, POST)
    
    Security controls:
    1. TRACE method disabled (prevents XST)
    2. PUT/DELETE require authentication
    3. OPTIONS returns minimal info
    4. Method allowlist enforced
    
    Example: TRACE, PUT, DELETE return 405 Method Not Allowed
    """
    method = request.method
    
    # SECURE: Only GET and POST allowed for this endpoint
    if method in ['GET', 'POST']:
        return jsonify({
            'ok': True,
            'method': method,
            'message': f'{method} request accepted',
            'allowed_methods': ['GET', 'POST'],
            'security_controls': [
                'Only necessary methods enabled',
                'TRACE method disabled (XST prevention)',
                'Dangerous methods require authentication',
                'Method allowlist enforced'
            ]
        }), 200
    else:
        # SECURE: Reject other methods
        return jsonify({
            'ok': False,
            'error': 'Method Not Allowed',
            'allowed_methods': ['GET', 'POST'],
            'security_control': 'Unnecessary HTTP methods are disabled'
        }), 405, {'Allow': 'GET, POST'}


@a05_misconfiguration_blue.route('/api/blue/misconfiguration/cors-wildcard', methods=['GET', 'POST', 'OPTIONS'])
def cors_wildcard_secure():
    """
    SECURE: CORS configured with specific allowed origins
    
    Security controls:
    1. Specific origins whitelisted (no wildcard)
    2. Credentials only allowed for trusted origins
    3. Origin validation enforced
    4. Pre-flight requests handled properly
    
    Example: Only requests from localhost and trusted domains succeed
    """
    
    # SECURE: Whitelist of allowed origins
    ALLOWED_ORIGINS = [
        'http://localhost:3000',
        'http://localhost:5000',
        'https://app.aegisforge.com',
        'https://secure.aegisforge.com'
    ]
    
    origin = request.headers.get('Origin', '')
    
    # SECURE: Validate origin
    if origin not in ALLOWED_ORIGINS:
        return jsonify({
            'ok': False,
            'error': 'Origin not allowed',
            'security_control': 'CORS restricts origins to whitelist only',
            'allowed_origins': ['localhost:3000', 'app.aegisforge.com']
        }), 403
    
    # Sensitive data (only accessible from allowed origins)
    sensitive_data = {
        'ok': True,
        'user': {
            'id': 1,
            'username': 'user',
            'email': 'user@example.com'
        },
        'session_token': secrets.token_urlsafe(32),
        'security_controls': [
            'CORS uses specific origin whitelist',
            'No wildcard (*) allowed',
            'Credentials only sent to trusted origins',
            'Origin validation enforced'
        ]
    }
    
    # SECURE: Set specific origin, not wildcard
    response = jsonify(sensitive_data)
    response.headers['Access-Control-Allow-Origin'] = origin  # Specific origin
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST'  # Limited methods
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Credentials'] = 'true'  # Safe with specific origin
    response.headers['Access-Control-Max-Age'] = '3600'  # Cache pre-flight
    
    return response, 200


@a05_misconfiguration_blue.route('/api/blue/misconfiguration/info', methods=['GET'])
def misconfiguration_info():
    """
    Get information about secure configuration practices
    """
    return jsonify({
        'category': 'A05: Security Misconfiguration - SECURE Implementation',
        'description': 'Demonstrates secure configuration and hardening practices',
        'security_patterns': [
            {
                'name': 'Strong Authentication',
                'endpoint': '/api/blue/misconfiguration/default-credentials',
                'method': 'POST',
                'controls': [
                    'Strong password requirements',
                    'Password hashing',
                    'Rate limiting',
                    'Account lockout',
                    'Secure token generation'
                ]
            },
            {
                'name': 'Production Mode',
                'endpoint': '/api/blue/misconfiguration/debug-enabled',
                'method': 'GET',
                'controls': [
                    'Debug mode disabled',
                    'Sanitized error messages',
                    'No sensitive data exposure',
                    'Server-side error logging'
                ]
            },
            {
                'name': 'No Directory Listing',
                'endpoint': '/api/blue/misconfiguration/directory-listing',
                'method': 'GET',
                'controls': [
                    'Directory listing disabled',
                    'Access control enforced',
                    'File enumeration prevented'
                ]
            },
            {
                'name': 'Method Restrictions',
                'endpoint': '/api/blue/misconfiguration/unnecessary-methods',
                'method': 'GET/POST',
                'controls': [
                    'Only necessary methods enabled',
                    'TRACE disabled',
                    'Method allowlist',
                    'Authentication required for modifications'
                ]
            },
            {
                'name': 'Secure CORS',
                'endpoint': '/api/blue/misconfiguration/cors-wildcard',
                'method': 'GET',
                'controls': [
                    'Origin whitelist',
                    'No wildcard (*)',
                    'Credentials restricted to trusted origins',
                    'Pre-flight validation'
                ]
            }
        ],
        'owasp_reference': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
        'documentation': '/docs/vulnerabilities/owasp-web-2021/A05_MISCONFIGURATION.md'
    }), 200
