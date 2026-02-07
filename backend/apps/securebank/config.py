"""
SecureBank Configuration
Loads configuration from environment variables with secure defaults
"""

import os
import secrets
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# ============================================================================
# HELPER FUNCTIONS
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
# SECUREBANK CONFIGURATION
# ============================================================================

class SecureBankConfig:
    """SecureBank configuration"""
    
    # Flask
    DEBUG = get_env('SECUREBANK_DEBUG', 'True', cast=bool)
    
    # SECURITY WARNING: Generate a strong secret key for production!
    # Use: python -c "import secrets; print(secrets.token_hex(32))"
    SECRET_KEY = get_env('SECUREBANK_SECRET_KEY', secrets.token_hex(32))
    
    # Database
    DB_PATH = get_env('SECUREBANK_DB_PATH', str(BASE_DIR / 'securebank.db'))
    
    # CORS
    CORS_ORIGINS = get_env('SECUREBANK_CORS_ORIGINS', 'http://localhost:3000,http://localhost:5000,http://localhost:5001').split(',')
    
    # Session
    SESSION_LIFETIME = get_env('SECUREBANK_SESSION_LIFETIME', '3600', cast=int)
    
    # Logging
    LOG_LEVEL = get_env('SECUREBANK_LOG_LEVEL', 'INFO')
    LOG_FILE = get_env('SECUREBANK_LOG_FILE', str(BASE_DIR / 'logs' / 'securebank.log'))

# ============================================================================
# TEST CREDENTIALS (EDUCATIONAL ONLY)
# ============================================================================

class SecureBankTestCredentials:
    """
    Test credentials for SecureBank educational demos
    
    WARNING: These are for Red Team vulnerable endpoints only!
    NEVER use in production!
    """
    
    # SecureBank test users
    ALICE_PASSWORD = get_env('TEST_USER_ALICE_PASSWORD', 'password123')
    BOB_PASSWORD = get_env('TEST_USER_BOB_PASSWORD', 'securepass456')
    ADMIN_PASSWORD = get_env('TEST_USER_ADMIN_PASSWORD', 'admin123')
    CAROL_PASSWORD = get_env('TEST_USER_CAROL_PASSWORD', 'carol789')

# ============================================================================
# PRODUCTION CONFIGURATION
# ============================================================================

class SecureBankProductionConfig(SecureBankConfig):
    """Production configuration with enhanced security"""
    
    DEBUG = False
    
    # SECURITY: These MUST be set via environment variables in production
    SECRET_KEY = get_env('SECUREBANK_SECRET_KEY', required=True)
    
    # Strict CORS
    CORS_ORIGINS = get_env('SECUREBANK_CORS_ORIGINS', required=True).split(',')

# ============================================================================
# CONFIGURATION SELECTION
# ============================================================================

config = {
    'development': SecureBankConfig,
    'production': SecureBankProductionConfig,
    'default': SecureBankConfig
}

def get_config(env=None):
    """Get configuration based on environment"""
    if env is None:
        env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
