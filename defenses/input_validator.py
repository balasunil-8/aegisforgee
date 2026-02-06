"""
AegisForge Input Validation Module
Provides security controls for input sanitization and validation
"""

import re
import html
from urllib.parse import urlparse

def sanitize_sql_input(value: str) -> str:
    """
    Sanitize input to prevent SQL injection
    Note: This is educational - use parameterized queries in production!
    """
    if not value:
        return value
    
    # Remove common SQL injection characters
    dangerous_chars = ["'", '"', ";", "--", "/*", "*/", "xp_", "sp_", "UNION", "SELECT", "DROP", "INSERT", "UPDATE", "DELETE"]
    sanitized = value
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, "")
    
    return sanitized

def sanitize_xss_input(value: str) -> str:
    """
    Sanitize input to prevent XSS attacks
    HTML encodes potentially dangerous characters
    """
    if not value:
        return value
    
    # HTML encode the input
    return html.escape(value)

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_username(username: str) -> bool:
    """Validate username format (alphanumeric, underscore, dash, 3-20 chars)"""
    pattern = r'^[a-zA-Z0-9_-]{3,20}$'
    return bool(re.match(pattern, username))

def validate_url(url: str, allow_private: bool = False) -> tuple[bool, str]:
    """
    Validate URL and check for SSRF risks
    Returns: (is_valid, error_message)
    """
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP and HTTPS protocols are allowed"
        
        # Check for private IP ranges (SSRF protection)
        if not allow_private:
            hostname = parsed.hostname or parsed.netloc
            
            # Block localhost
            if hostname in ['localhost', '127.0.0.1', '0.0.0.0', '::1']:
                return False, "Localhost access is blocked"
            
            # Block private IP ranges
            private_patterns = [
                r'^10\.',
                r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
                r'^192\.168\.',
                r'^169\.254\.',  # Link-local
                r'^fe80:',       # IPv6 link-local
                r'^fc00:',       # IPv6 private
            ]
            
            for pattern in private_patterns:
                if re.match(pattern, hostname):
                    return False, f"Private IP range access is blocked"
        
        return True, ""
    
    except Exception as e:
        return False, f"Invalid URL format: {str(e)}"

def validate_file_path(path: str) -> tuple[bool, str]:
    """
    Validate file path to prevent directory traversal
    Returns: (is_valid, error_message)
    """
    # Check for directory traversal patterns
    dangerous_patterns = ['../', '..\\', '%2e%2e', '....', './.']
    
    for pattern in dangerous_patterns:
        if pattern in path.lower():
            return False, "Directory traversal detected"
    
    # Check for absolute paths (should use relative paths)
    if path.startswith('/') or (len(path) > 1 and path[1] == ':'):
        return False, "Absolute paths are not allowed"
    
    return True, ""

def validate_positive_integer(value: any, min_val: int = 1, max_val: int = 1000000) -> tuple[bool, int, str]:
    """
    Validate positive integer with range checking
    Returns: (is_valid, value, error_message)
    """
    try:
        num = int(value)
        if num < min_val:
            return False, 0, f"Value must be at least {min_val}"
        if num > max_val:
            return False, 0, f"Value must not exceed {max_val}"
        return True, num, ""
    except (ValueError, TypeError):
        return False, 0, "Value must be a valid integer"

def sanitize_command_input(value: str) -> str:
    """
    Sanitize input to prevent command injection
    Removes shell metacharacters
    """
    if not value:
        return value
    
    # Remove command injection characters
    dangerous_chars = [';', '&', '|', '$', '`', '>', '<', '\n', '\r', '(', ')', '{', '}']
    sanitized = value
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, "")
    
    return sanitized

def validate_json_structure(data: dict, required_fields: list, allowed_fields: list = None) -> tuple[bool, str]:
    """
    Validate JSON structure to prevent mass assignment
    Returns: (is_valid, error_message)
    """
    # Check required fields
    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"
    
    # Check for unauthorized fields (if allowlist provided)
    if allowed_fields:
        for field in data.keys():
            if field not in allowed_fields:
                return False, f"Unauthorized field: {field}"
    
    return True, ""
