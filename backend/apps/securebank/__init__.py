"""
SecureBank Package
Educational banking application for AegisForge
"""

from .securebank_red_api import create_red_team_api
from .securebank_blue_api import create_blue_team_api
from .database import init_database, get_connection
from .seed_data import seed_database

__version__ = '1.0.0'
__all__ = [
    'create_red_team_api',
    'create_blue_team_api',
    'init_database',
    'get_connection',
    'seed_database'
]
