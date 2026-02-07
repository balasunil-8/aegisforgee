"""
AegisForge Backend Centralized Configuration
Loads configuration from environment variables with secure defaults
"""

import os
import secrets
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# ============================================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================================

def get_env(key, default=None, required=False, cast=str):
    """
    Get environment variable with type casting and validation
    
    Args:
        key: Environment variable name
        default: Default value if not found
        required: Raise error if not found
        cast: Type to cast the value to (str, int, bool)
    
    Returns:
        Environment variable value or default
    """
    value = os.environ.get(key, default)
    
    if required and value is None:
        raise ValueError(f"Required environment variable '{key}' not set")
    
    if value is None:
        return None
    
    # Type casting
    if cast == bool:
        return value.lower() in ('true', '1', 'yes', 'on')
    elif cast == int:
        return int(value)
    elif cast == float:
        return float(value)
    else:
        return value

# ============================================================================
# BACKEND CONFIGURATION
# ============================================================================

class BackendConfig:
    """Backend configuration"""
    
    # Flask
    ENV = get_env('FLASK_ENV', 'development')
    DEBUG = get_env('FLASK_DEBUG', 'True', cast=bool)
    SECRET_KEY = get_env('FLASK_SECRET_KEY', secrets.token_hex(32))
    
    # Database
    DB_TYPE = get_env('DB_TYPE', 'sqlite')
    DB_PATH = get_env('DB_PATH', str(BASE_DIR / 'aegisforge.db'))
    DATABASE_URL = get_env('DATABASE_URL', f'sqlite:///{DB_PATH}')
    
    # Session
    SESSION_COOKIE_SECURE = get_env('SESSION_COOKIE_SECURE', 'False', cast=bool)
    SESSION_COOKIE_HTTPONLY = get_env('SESSION_COOKIE_HTTPONLY', 'True', cast=bool)
    SESSION_COOKIE_SAMESITE = get_env('SESSION_COOKIE_SAMESITE', 'Lax')
    PERMANENT_SESSION_LIFETIME = get_env('PERMANENT_SESSION_LIFETIME', '3600', cast=int)
    
    # CORS
    CORS_ORIGINS = get_env('CORS_ORIGINS', 'http://localhost:3000,http://localhost:5000,http://localhost:5001').split(',')
    CORS_ALLOW_CREDENTIALS = get_env('CORS_ALLOW_CREDENTIALS', 'True', cast=bool)
    
    # Logging
    LOG_LEVEL = get_env('LOG_LEVEL', 'INFO')
    LOG_FILE = get_env('LOG_FILE', str(BASE_DIR / 'logs' / 'aegisforge.log'))
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = get_env('RATE_LIMIT_ENABLED', 'True', cast=bool)
    RATE_LIMIT_DEFAULT = get_env('RATE_LIMIT_DEFAULT', '100 per hour')
    RATE_LIMIT_STORAGE_URL = get_env('RATE_LIMIT_STORAGE_URL', 'memory://')

# ============================================================================
# TEST CREDENTIALS (EDUCATIONAL ONLY)
# ============================================================================

class TestCredentials:
    """
    Test credentials for educational purposes
    
    WARNING: These are for Red Team vulnerable endpoints only!
    NEVER use in production!
    """
    
    # SecureBank test users
    ALICE_PASSWORD = get_env('TEST_USER_ALICE_PASSWORD', 'password123')
    BOB_PASSWORD = get_env('TEST_USER_BOB_PASSWORD', 'securepass456')
    ADMIN_PASSWORD = get_env('TEST_USER_ADMIN_PASSWORD', 'admin123')
    CAROL_PASSWORD = get_env('TEST_USER_CAROL_PASSWORD', 'carol789')
    
    # OWASP A05 default credentials (misconfiguration demo)
    DEMO_ADMIN_USERNAME = get_env('DEMO_ADMIN_USERNAME', 'admin')
    DEMO_ADMIN_PASSWORD = get_env('DEMO_ADMIN_PASSWORD', 'admin')
    DEMO_ROOT_USERNAME = get_env('DEMO_ROOT_USERNAME', 'root')
    DEMO_ROOT_PASSWORD = get_env('DEMO_ROOT_PASSWORD', 'root')

# ============================================================================
# PRODUCTION CONFIGURATION
# ============================================================================

class ProductionConfig(BackendConfig):
    """Production configuration with enhanced security"""
    
    DEBUG = False
    ENV = 'production'
    
    # Secure cookies
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    def __init__(self):
        """Initialize production config with required environment variables"""
        super().__init__()
        # SECURITY: These MUST be set via environment variables in production
        self.SECRET_KEY = get_env('FLASK_SECRET_KEY', required=True)
        self.DATABASE_URL = get_env('DATABASE_URL', required=True)
        # Strict CORS
        self.CORS_ORIGINS = get_env('CORS_ORIGINS', required=True).split(',')

# ============================================================================
# CONFIGURATION SELECTION
# ============================================================================

config = {
    'development': BackendConfig,
    'production': ProductionConfig,
    'default': BackendConfig
}

def get_config(env=None):
    """Get configuration based on environment"""
    if env is None:
        env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
