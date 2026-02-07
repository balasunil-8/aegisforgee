"""
Secrets Manager
Manages credentials and secrets for AegisForge
"""

import os
import secrets
import hashlib
from typing import Optional, Dict


class SecretManager:
    """Manage application secrets and credentials"""
    
    def __init__(self):
        """Initialize secrets manager"""
        self._secrets_cache: Dict[str, str] = {}
    
    @staticmethod
    def generate_secret_key(length: int = 32) -> str:
        """
        Generate a cryptographically secure secret key
        
        Args:
            length: Length of the secret key in bytes
        
        Returns:
            Hexadecimal string representation of the secret key
        """
        return secrets.token_hex(length)
    
    @staticmethod
    def generate_password(length: int = 16) -> str:
        """
        Generate a secure random password
        
        Args:
            length: Length of the password
        
        Returns:
            Secure random password
        """
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def hash_password(password: str, algorithm: str = 'sha256') -> str:
        """
        Hash a password using the specified algorithm
        
        Args:
            password: Password to hash
            algorithm: Hashing algorithm (default: sha256)
        
        Returns:
            Hashed password
        
        Note:
            For production use, consider using bcrypt or argon2 instead
        """
        if algorithm == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(password.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def get_secret(self, key: str, default: Optional[str] = None, 
                   generate_if_missing: bool = False) -> Optional[str]:
        """
        Get a secret from environment or cache
        
        Args:
            key: Secret key name
            default: Default value if not found
            generate_if_missing: Generate a new secret if missing
        
        Returns:
            Secret value
        """
        # Check cache first
        if key in self._secrets_cache:
            return self._secrets_cache[key]
        
        # Check environment
        value = os.environ.get(key)
        
        if value is None:
            if generate_if_missing:
                value = self.generate_secret_key()
                self._secrets_cache[key] = value
            else:
                value = default
        
        return value
    
    def set_secret(self, key: str, value: str):
        """
        Set a secret in cache
        
        Args:
            key: Secret key name
            value: Secret value
        """
        self._secrets_cache[key] = value
    
    def get_test_credentials(self) -> Dict[str, str]:
        """
        Get test credentials from environment
        
        WARNING: For educational purposes only!
        
        Returns:
            Dictionary of test credentials
        """
        return {
            'alice': os.environ.get('TEST_USER_ALICE_PASSWORD', 'password123'),
            'bob': os.environ.get('TEST_USER_BOB_PASSWORD', 'securepass456'),
            'admin': os.environ.get('TEST_USER_ADMIN_PASSWORD', 'admin123'),
            'carol': os.environ.get('TEST_USER_CAROL_PASSWORD', 'carol789'),
        }
    
    def get_demo_credentials(self) -> Dict[str, Dict[str, str]]:
        """
        Get demo credentials for OWASP A05 misconfiguration demos
        
        WARNING: For educational purposes only!
        
        Returns:
            Dictionary of demo credentials
        """
        return {
            'admin': {
                'username': os.environ.get('DEMO_ADMIN_USERNAME', 'admin'),
                'password': os.environ.get('DEMO_ADMIN_PASSWORD', 'admin')
            },
            'root': {
                'username': os.environ.get('DEMO_ROOT_USERNAME', 'root'),
                'password': os.environ.get('DEMO_ROOT_PASSWORD', 'root')
            }
        }


# Global instance
secret_manager = SecretManager()
