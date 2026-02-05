"""
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
