"""
AegisForge Defense Module Library
Comprehensive security defense implementations for Blue Team endpoints
"""

from .input_validator import (
    validate_sql_input,
    sanitize_xss,
    validate_command_input,
    validate_path_input,
    validate_email,
    validate_password_strength
)

from .security_headers import (
    get_csp_header,
    generate_csrf_token,
    validate_csrf_token,
    get_security_headers
)

from .rate_limiter import (
    check_rate_limit,
    RateLimiter,
    reset_rate_limit
)

from .access_control import (
    check_ownership,
    require_admin,
    check_rbac,
    validate_session
)

__all__ = [
    'validate_sql_input',
    'sanitize_xss',
    'validate_command_input',
    'validate_path_input',
    'validate_email',
    'validate_password_strength',
    'get_csp_header',
    'generate_csrf_token',
    'validate_csrf_token',
    'get_security_headers',
    'check_rate_limit',
    'RateLimiter',
    'reset_rate_limit',
    'check_ownership',
    'require_admin',
    'check_rbac',
    'validate_session'
AegisForge Defense Modules
Security controls for the Blue Team mode
"""

from .input_validator import *
from .security_headers import *
from .rate_limiter import *
from .waf_rules import *

__all__ = [
    'sanitize_sql_input',
    'sanitize_xss_input',
    'validate_email',
    'validate_username',
    'validate_url',
    'validate_file_path',
    'validate_positive_integer',
    'sanitize_command_input',
    'validate_json_structure',
    'add_security_headers',
    'add_cors_headers',
    'get_security_headers_info',
    'RateLimiter',
    'get_rate_limiter',
    'check_rate_limit',
    'WAF',
    'get_waf',
    'check_for_attacks'
]
