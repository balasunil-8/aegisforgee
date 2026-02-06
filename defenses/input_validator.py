"""
Input Validation Module
Provides validation and sanitization functions for user inputs
AegisForge Input Validation Module
Provides security controls for input sanitization and validation
"""

import re
import html
from urllib.parse import urlparse
import os


def validate_sql_input(user_input):
    """
    Validate input for SQL injection patterns
    Returns: (is_valid, error_message)
    """
    if not user_input:
        return True, None
    
    # SQL injection patterns to detect
    sql_patterns = [
        r"(\bunion\b.*\bselect\b)",
        r"(\bselect\b.*\bfrom\b)",
        r"(\bdrop\b.*\btable\b)",
        r"(\binsert\b.*\binto\b)",
        r"(\bdelete\b.*\bfrom\b)",
        r"(\bupdate\b.*\bset\b)",
        r"(--|\#|\/\*)",
        r"(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
        r"(\band\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
        r"(\bxp_cmdshell\b)",
        r"(\bexec\b.*\()",
        r"(;.*\b(drop|delete|update|insert)\b)"
    ]
    
    input_lower = user_input.lower()
    for pattern in sql_patterns:
        if re.search(pattern, input_lower, re.IGNORECASE):
            return False, f"Potential SQL injection detected: pattern matched"
    
    return True, None


def sanitize_xss(user_input):
    """
    Sanitize input to prevent XSS attacks
    Returns: sanitized string
    """
    if not user_input:
        return ""
    
    # HTML entity encode
    sanitized = html.escape(user_input)
    
    # Additional sanitization for common XSS patterns
    dangerous_patterns = [
        (r'<script[^>]*>.*?</script>', ''),
        (r'javascript:', ''),
        (r'on\w+\s*=', ''),  # onclick, onerror, etc.
        (r'<iframe[^>]*>.*?</iframe>', ''),
        (r'<object[^>]*>.*?</object>', ''),
        (r'<embed[^>]*>', ''),
    ]
    
    for pattern, replacement in dangerous_patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
    
    return sanitized


def validate_command_input(command):
    """
    Validate command input to prevent command injection
    Returns: (is_valid, error_message)
    """
    if not command:
        return True, None
    
    # Dangerous command injection characters
    dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r', '>', '<', '(', ')']
    
    for char in dangerous_chars:
        if char in command:
            return False, f"Dangerous character detected: {char}"
    
    # Check for command chaining patterns
    command_patterns = [
        r'&&',
        r'\|\|',
        r';\s*\w+',
        r'\$\(',
        r'`[^`]+`'
    ]
    
    for pattern in command_patterns:
        if re.search(pattern, command):
            return False, "Command chaining pattern detected"
    
    return True, None


def validate_path_input(path):
    """
    Validate file path to prevent path traversal
    Returns: (is_valid, error_message, sanitized_path)
    """
    if not path:
        return True, None, ""
    
    # Check for path traversal patterns
    if '..' in path:
        return False, "Path traversal detected", None
    
    # Check for absolute paths
    if path.startswith('/') or path.startswith('\\'):
        return False, "Absolute path not allowed", None
    
    # Check for Windows drive letters
    if re.match(r'^[a-zA-Z]:', path):
        return False, "Drive letter path not allowed", None
    
    # Normalize path
    normalized = os.path.normpath(path)
    
    # Final check after normalization
    if '..' in normalized or normalized.startswith('/') or normalized.startswith('\\'):
        return False, "Invalid path after normalization", None
    
    return True, None, normalized


def validate_email(email):
    """
    Validate email format
    Returns: (is_valid, error_message)
    """
    if not email:
        return False, "Email is required"
    
    # RFC 5322 simplified email regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    # Check length
    if len(email) > 254:
        return False, "Email too long"
    
    return True, None


def validate_password_strength(password):
    """
    Validate password strength
    Returns: (is_valid, error_message, strength_score)
    """
    if not password:
        return False, "Password is required", 0
    
    score = 0
    issues = []
    
    # Length check
    if len(password) < 8:
        issues.append("Password must be at least 8 characters")
    else:
        score += 1
    
    if len(password) >= 12:
        score += 1
    
    # Complexity checks
    if not re.search(r'[a-z]', password):
        issues.append("Password must contain lowercase letters")
    else:
        score += 1
    
    if not re.search(r'[A-Z]', password):
        issues.append("Password must contain uppercase letters")
    else:
        score += 1
    
    if not re.search(r'\d', password):
        issues.append("Password must contain numbers")
    else:
        score += 1
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        issues.append("Password must contain special characters")
    else:
        score += 1
    
    # Common password check
    common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein', 'welcome']
    if password.lower() in common_passwords:
        issues.append("Password is too common")
        score = 0
    
    if issues:
        return False, "; ".join(issues), score
    
    return True, None, score


def validate_url(url, allow_private=False):
    """
    Validate URL and check for SSRF attempts
    Returns: (is_valid, error_message)
    """
    if not url:
        return False, "URL is required"
    

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
            return False, "Only HTTP/HTTPS URLs allowed"
        
        # Check for localhost/private IPs
        if not allow_private:
            hostname = parsed.hostname or ''
            
            # Localhost variations
            localhost_patterns = [
                'localhost',
                '127.0.0.1',
                '0.0.0.0',
                '::1',
                '0:0:0:0:0:0:0:1'
            ]
            
            if hostname.lower() in localhost_patterns:
                return False, "Localhost URLs not allowed"
            
            # Private IP ranges
            if hostname.startswith('10.') or hostname.startswith('192.168.') or hostname.startswith('172.'):
                # More precise check for 172.16.0.0/12
                if hostname.startswith('172.'):
                    try:
                        second_octet = int(hostname.split('.')[1])
                        if 16 <= second_octet <= 31:
                            return False, "Private IP range not allowed"
                    except (ValueError, IndexError):
                        pass
                else:
                    return False, "Private IP range not allowed"
            
            # Link-local
            if hostname.startswith('169.254.'):
                return False, "Link-local IP not allowed"
        
        return True, None
        
    except Exception as e:
        return False, f"Invalid URL: {str(e)}"


def validate_json_input(data, allowed_fields=None):
    """
    Validate JSON input and filter to allowed fields
    Returns: (is_valid, error_message, filtered_data)
    """
    if not isinstance(data, dict):
        return False, "Input must be a JSON object", None
    
    if allowed_fields is None:
        return True, None, data
    
    # Filter to allowed fields only
    filtered = {k: v for k, v in data.items() if k in allowed_fields}
    
    # Check for suspicious field names
    suspicious_patterns = ['__', 'prototype', 'constructor']
    for key in data.keys():
        if any(pattern in key.lower() for pattern in suspicious_patterns):
            return False, f"Suspicious field name: {key}", None
    
    return True, None, filtered


def validate_integer_range(value, min_val=None, max_val=None):
    """
    Validate integer is within range
    Returns: (is_valid, error_message, value)
    """
    try:
        int_val = int(value)
        
        if min_val is not None and int_val < min_val:
            return False, f"Value must be at least {min_val}", None
        
        if max_val is not None and int_val > max_val:
            return False, f"Value must be at most {max_val}", None
        
        return True, None, int_val
        
    except (ValueError, TypeError):
        return False, "Invalid integer value", None
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
