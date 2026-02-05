"""
AegisForge Mode Switching Module
Manages Red Team (offensive) vs Blue Team (defensive) modes
"""

from flask import session
from enum import Enum

class SecurityMode(Enum):
    RED_TEAM = "red"    # Vulnerable endpoints for exploitation practice
    BLUE_TEAM = "blue"  # Hardened endpoints showing security best practices

# Default mode
DEFAULT_MODE = SecurityMode.RED_TEAM

def get_current_mode():
    """Get the current security mode from session"""
    mode_str = session.get('security_mode', DEFAULT_MODE.value)
    try:
        return SecurityMode(mode_str)
    except ValueError:
        return DEFAULT_MODE

def set_mode(mode: SecurityMode):
    """Set the security mode in session"""
    session['security_mode'] = mode.value
    session.modified = True

def toggle_mode():
    """Toggle between Red Team and Blue Team modes"""
    current = get_current_mode()
    new_mode = SecurityMode.BLUE_TEAM if current == SecurityMode.RED_TEAM else SecurityMode.RED_TEAM
    set_mode(new_mode)
    return new_mode

def is_red_team_mode():
    """Check if currently in Red Team (vulnerable) mode"""
    return get_current_mode() == SecurityMode.RED_TEAM

def is_blue_team_mode():
    """Check if currently in Blue Team (hardened) mode"""
    return get_current_mode() == SecurityMode.BLUE_TEAM

def get_mode_info():
    """Get information about the current mode"""
    mode = get_current_mode()
    
    if mode == SecurityMode.RED_TEAM:
        return {
            'mode': 'red',
            'name': 'Red Team',
            'description': 'Offensive Security - Vulnerable endpoints for exploitation practice',
            'color': '#DC2626',
            'icon': '🔴',
            'purpose': 'Learn to identify and exploit vulnerabilities'
        }
    else:
        return {
            'mode': 'blue',
            'name': 'Blue Team',
            'description': 'Defensive Security - Hardened endpoints with security controls',
            'color': '#1E40AF',
            'icon': '🔵',
            'purpose': 'Learn security best practices and defensive techniques'
        }
