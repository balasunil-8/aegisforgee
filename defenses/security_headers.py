"""
Security Headers Module
Provides security header generation and CSRF protection
"""

import secrets
import hashlib
import time
from datetime import datetime, timedelta


# In-memory CSRF token store (in production, use Redis or database)
_csrf_tokens = {}


def get_csp_header():
    """
    Generate Content Security Policy header
    Returns: CSP meta tag HTML
    """
    csp_directives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self'",
AegisForge Security Headers Module
Implements HTTP security headers for defense-in-depth
"""

from flask import Response

def add_security_headers(response: Response) -> Response:
    """
    Add comprehensive security headers to HTTP responses
    Implements OWASP security header recommendations
    """
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Enable XSS protection (legacy browsers)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Content Security Policy (CSP)
    csp_directives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'",  # Relaxed for demo
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'"
    ]
    
    csp_string = "; ".join(csp_directives)
    return f'<meta http-equiv="Content-Security-Policy" content="{csp_string}">'


def generate_csrf_token(session_id=None):
    """
    Generate CSRF token for a session
    Returns: token string
    """
    if session_id is None:
        session_id = secrets.token_urlsafe(16)
    
    # Generate token
    token = secrets.token_urlsafe(32)
    
    # Store with expiration (1 hour)
    expiration = datetime.utcnow() + timedelta(hours=1)
    _csrf_tokens[token] = {
        'session_id': session_id,
        'created_at': datetime.utcnow(),
        'expires_at': expiration
    }
    
    # Clean up old tokens
    _cleanup_expired_tokens()
    
    return token


def validate_csrf_token(token, session_id=None):
    """
    Validate CSRF token
    Returns: boolean
    """
    if not token:
        return False
    
    token_data = _csrf_tokens.get(token)
    
    if not token_data:
        return False
    
    # Check expiration
    if datetime.utcnow() > token_data['expires_at']:
        del _csrf_tokens[token]
        return False
    
    # Check session ID if provided
    if session_id and token_data['session_id'] != session_id:
        return False
    
    return True


def invalidate_csrf_token(token):
    """
    Invalidate a CSRF token
    """
    if token in _csrf_tokens:
        del _csrf_tokens[token]


def _cleanup_expired_tokens():
    """
    Remove expired CSRF tokens
    """
    now = datetime.utcnow()
    expired = [token for token, data in _csrf_tokens.items() if now > data['expires_at']]
    for token in expired:
        del _csrf_tokens[token]


def get_security_headers():
    """
    Get complete set of security headers
    Returns: dict of header name -> value
    """
    return {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }


def get_cors_headers(allowed_origins=None):
    """
    Get CORS headers with whitelist
    Returns: dict of header name -> value
    """
    if allowed_origins is None:
        allowed_origins = ['http://localhost:5000', 'http://127.0.0.1:5000']
    
    return {
        'Access-Control-Allow-Origin': ','.join(allowed_origins),
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
        'Access-Control-Max-Age': '3600'
    }


def calculate_sri_hash(content):
    """
    Calculate Subresource Integrity hash for a script/style
    Returns: SRI hash string
    """
    sha384_hash = hashlib.sha384(content.encode('utf-8')).digest()
    import base64
    return f"sha384-{base64.b64encode(sha384_hash).decode('utf-8')}"


def generate_nonce():
    """
    Generate nonce for CSP script-src
    Returns: nonce string
    """
    return secrets.token_urlsafe(16)


def get_csp_with_nonce(nonce):
    """
    Generate CSP header with nonce
    Returns: CSP header value
    """
    return (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"img-src 'self' data: https:; "
        f"font-src 'self'; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'"
    )
    response.headers['Content-Security-Policy'] = "; ".join(csp_directives)
    
    # Strict Transport Security (HTTPS only)
    # Uncomment in production with HTTPS
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy (formerly Feature Policy)
    permissions_directives = [
        "geolocation=()",
        "microphone=()",
        "camera=()",
        "payment=()",
        "usb=()",
        "magnetometer=()"
    ]
    response.headers['Permissions-Policy'] = ", ".join(permissions_directives)
    
    # Remove server information disclosure
    response.headers['Server'] = 'AegisForge'
    
    # Cache control for sensitive data
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
    
    return response

def add_cors_headers(response: Response, allowed_origins: list = None) -> Response:
    """
    Add CORS headers with proper restrictions
    """
    if allowed_origins is None:
        allowed_origins = ['http://localhost:3000', 'http://localhost:5000']
    
    origin = response.headers.get('Origin')
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        response.headers['Access-Control-Allow-Origin'] = allowed_origins[0]
    
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Max-Age'] = '3600'
    
    return response

def get_security_headers_info() -> dict:
    """Return information about implemented security headers"""
    return {
        'headers': [
            {
                'name': 'X-Content-Type-Options',
                'value': 'nosniff',
                'purpose': 'Prevents MIME type sniffing attacks'
            },
            {
                'name': 'X-XSS-Protection',
                'value': '1; mode=block',
                'purpose': 'Enables browser XSS filtering'
            },
            {
                'name': 'X-Frame-Options',
                'value': 'DENY',
                'purpose': 'Prevents clickjacking attacks'
            },
            {
                'name': 'Content-Security-Policy',
                'value': 'default-src self; ...',
                'purpose': 'Restricts resource loading to prevent XSS'
            },
            {
                'name': 'Referrer-Policy',
                'value': 'strict-origin-when-cross-origin',
                'purpose': 'Controls referrer information disclosure'
            },
            {
                'name': 'Permissions-Policy',
                'value': 'geolocation=(), camera=(), ...',
                'purpose': 'Disables unnecessary browser features'
            }
        ],
        'compliance': ['OWASP', 'PCI-DSS', 'GDPR']
    }
