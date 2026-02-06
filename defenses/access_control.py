"""
Access Control Module
Provides RBAC, ownership validation, and authorization helpers
"""

from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from datetime import datetime


def check_ownership(resource_user_id, current_user_id):
    """
    Check if current user owns the resource
    
    Args:
        resource_user_id: User ID who owns the resource
        current_user_id: Current authenticated user ID
        
    Returns:
        boolean - True if owner, False otherwise
    """
    return str(resource_user_id) == str(current_user_id)


def check_rbac(user_role, required_roles):
    """
    Check Role-Based Access Control
    
    Args:
        user_role: Role of the current user
        required_roles: List of allowed roles or single role string
        
    Returns:
        boolean - True if authorized, False otherwise
    """
    if isinstance(required_roles, str):
        required_roles = [required_roles]
    
    return user_role in required_roles


def require_ownership(get_resource_owner_func):
    """
    Decorator to require resource ownership
    
    Usage:
        @require_ownership(lambda user_id: User.query.get(user_id))
        def view_user(user_id):
            ...
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            
            # Get resource owner ID
            resource_id = kwargs.get('id') or kwargs.get('user_id') or kwargs.get('resource_id')
            if resource_id is None:
                return jsonify({'error': 'Resource ID not provided'}), 400
            
            resource_owner = get_resource_owner_func(resource_id)
            
            if resource_owner is None:
                return jsonify({'error': 'Resource not found'}), 404
            
            # Check ownership
            if not check_ownership(resource_owner, current_user_id):
                return jsonify({'error': 'Access denied', 'reason': 'Not the resource owner'}), 403
            
            return f(*args, **kwargs)
        
        return wrapper
    return decorator


def require_admin(f):
    """
    Decorator to require admin role
    
    Usage:
        @app.route('/admin/users')
        @require_admin
        def list_users():
            ...
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        
        # Get current user from JWT
        current_user_id = get_jwt_identity()
        
        # Check if user is admin (this would typically query the database)
        # For this example, we'll check a custom claim or user attribute
        # In a real app, query User.query.get(current_user_id).is_admin
        
        from flask import current_app
        try:
            # Try to get user from database if SQLAlchemy is available
            if hasattr(current_app, 'db'):
                # Assuming User model exists
                from models import User
                user = User.query.filter_by(username=current_user_id).first() or \
                       User.query.get(current_user_id)
                
                if user and user.is_admin:
                    return f(*args, **kwargs)
        except:
            pass
        
        return jsonify({'error': 'Access denied', 'reason': 'Admin privileges required'}), 403
    
    return wrapper


def require_role(required_roles):
    """
    Decorator to require specific roles
    
    Usage:
        @app.route('/moderator/posts')
        @require_role(['admin', 'moderator'])
        def moderate_posts():
            ...
    """
    if isinstance(required_roles, str):
        required_roles = [required_roles]
    
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            
            # Get user role (this would typically query the database)
            from flask import current_app
            try:
                if hasattr(current_app, 'db'):
                    from models import User
                    user = User.query.filter_by(username=current_user_id).first() or \
                           User.query.get(current_user_id)
                    
                    if user and check_rbac(user.role, required_roles):
                        return f(*args, **kwargs)
            except:
                pass
            
            return jsonify({
                'error': 'Access denied',
                'reason': f'Requires one of roles: {", ".join(required_roles)}'
            }), 403
        
        return wrapper
    return decorator


def validate_session(session_data, max_age_seconds=3600):
    """
    Validate session data is not expired
    
    Args:
        session_data: dict with 'created_at' or 'last_activity' timestamp
        max_age_seconds: maximum session age in seconds
        
    Returns:
        (is_valid, reason)
    """
    if not session_data:
        return False, "No session data"
    
    # Check for timestamp
    timestamp = session_data.get('created_at') or session_data.get('last_activity')
    
    if not timestamp:
        return False, "No timestamp in session"
    
    # Parse timestamp
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except ValueError:
            return False, "Invalid timestamp format"
    
    # Check age
    age = (datetime.utcnow() - timestamp).total_seconds()
    
    if age > max_age_seconds:
        return False, f"Session expired ({int(age)}s old)"
    
    return True, None


def check_permission(user, resource, action):
    """
    Check if user has permission to perform action on resource
    
    Args:
        user: User object
        resource: Resource object or resource type string
        action: Action string ('read', 'write', 'delete', etc.)
        
    Returns:
        boolean - True if permitted, False otherwise
    """
    # Admin has all permissions
    if hasattr(user, 'is_admin') and user.is_admin:
        return True
    
    # Check ownership
    if hasattr(resource, 'user_id') and hasattr(user, 'id'):
        if resource.user_id == user.id:
            return True  # Owner has all permissions
    
    # Role-based permissions
    if hasattr(user, 'role'):
        # Define role permissions
        role_permissions = {
            'admin': ['read', 'write', 'delete', 'admin'],
            'moderator': ['read', 'write', 'moderate'],
            'user': ['read', 'write_own'],
            'guest': ['read']
        }
        
        allowed_actions = role_permissions.get(user.role, [])
        return action in allowed_actions
    
    return False


def get_allowed_fields(user_role, resource_type):
    """
    Get allowed fields for a role and resource type
    Prevents mass assignment vulnerabilities
    
    Args:
        user_role: Role of the user
        resource_type: Type of resource ('user', 'post', etc.)
        
    Returns:
        list of allowed field names
    """
    # Define allowed fields per role and resource
    allowed_fields_map = {
        'user': {
            'admin': ['username', 'email', 'role', 'is_admin', 'password'],
            'moderator': ['username', 'email'],
            'user': ['username', 'email', 'password'],
            'guest': []
        },
        'post': {
            'admin': ['title', 'content', 'status', 'author_id'],
            'moderator': ['title', 'content', 'status'],
            'user': ['title', 'content'],
            'guest': []
        },
        'order': {
            'admin': ['status', 'items', 'user_id', 'total'],
            'user': ['items', 'shipping_address'],
            'guest': []
        }
    }
    
    resource_fields = allowed_fields_map.get(resource_type, {})
    return resource_fields.get(user_role, [])


def filter_sensitive_fields(data, user_role='user'):
    """
    Remove sensitive fields from response data based on user role
    
    Args:
        data: dict or list of dicts
        user_role: Role of the requesting user
        
    Returns:
        filtered data
    """
    # Fields to remove for non-admin users
    sensitive_fields = {
        'user': ['password', 'password_hash', 'api_key', 'secret_key', 'salt'],
        'moderator': ['password', 'password_hash'],
        'guest': ['password', 'password_hash', 'email', 'phone', 'api_key']
    }
    
    fields_to_remove = sensitive_fields.get(user_role, sensitive_fields['guest'])
    
    def filter_dict(d):
        if not isinstance(d, dict):
            return d
        return {k: v for k, v in d.items() if k not in fields_to_remove}
    
    if isinstance(data, list):
        return [filter_dict(item) for item in data]
    else:
        return filter_dict(data)
