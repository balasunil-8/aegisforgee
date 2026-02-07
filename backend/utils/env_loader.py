"""
Environment Variable Loader
Loads and validates environment variables for AegisForge
"""

import os
from pathlib import Path
from typing import Any, Optional, Union


class EnvironmentLoader:
    """Load and validate environment variables"""
    
    def __init__(self, env_file: Optional[str] = None):
        """
        Initialize environment loader
        
        Args:
            env_file: Path to .env file (optional)
        """
        self.env_file = env_file
        if env_file and Path(env_file).exists():
            self.load_from_file(env_file)
    
    def load_from_file(self, filepath: str):
        """
        Load environment variables from a file
        
        Args:
            filepath: Path to .env file
        """
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Parse KEY=VALUE
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Remove quotes if present
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    
                    # Only set if not already in environment
                    if key not in os.environ:
                        os.environ[key] = value
    
    def get(self, key: str, default: Any = None, required: bool = False, 
            cast: type = str) -> Any:
        """
        Get environment variable with type casting and validation
        
        Args:
            key: Environment variable name
            default: Default value if not found
            required: Raise error if not found
            cast: Type to cast the value to
        
        Returns:
            Environment variable value or default
        
        Raises:
            ValueError: If required variable is not set
        """
        value = os.environ.get(key, default)
        
        if required and value is None:
            raise ValueError(f"Required environment variable '{key}' not set")
        
        if value is None:
            return None
        
        # Type casting
        if cast == bool:
            return str(value).lower() in ('true', '1', 'yes', 'on')
        elif cast == int:
            return int(value)
        elif cast == float:
            return float(value)
        elif cast == list:
            return value.split(',')
        else:
            return value
    
    def get_str(self, key: str, default: str = None, required: bool = False) -> Optional[str]:
        """Get string environment variable"""
        return self.get(key, default, required, str)
    
    def get_int(self, key: str, default: int = None, required: bool = False) -> Optional[int]:
        """Get integer environment variable"""
        return self.get(key, default, required, int)
    
    def get_bool(self, key: str, default: bool = None, required: bool = False) -> Optional[bool]:
        """Get boolean environment variable"""
        return self.get(key, default, required, bool)
    
    def get_list(self, key: str, default: list = None, required: bool = False) -> Optional[list]:
        """Get list environment variable (comma-separated)"""
        return self.get(key, default, required, list)


def load_environment_variables(env_file: Optional[str] = None) -> EnvironmentLoader:
    """
    Load environment variables from file
    
    Args:
        env_file: Path to .env file (optional)
    
    Returns:
        EnvironmentLoader instance
    """
    return EnvironmentLoader(env_file)


# Global instance
env = EnvironmentLoader()
