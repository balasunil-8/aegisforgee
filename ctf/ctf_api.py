"""
AegisForge CTF - Flask API Endpoints

This module provides RESTful API endpoints for the CTF platform.
All endpoints return JSON responses with appropriate HTTP status codes.

API Endpoints:
    GET  /ctf/challenges              - List all challenges
    GET  /ctf/challenge/<id>          - Get challenge details
    POST /ctf/challenge/<id>/start    - Start a challenge
    POST /ctf/challenge/<id>/submit   - Submit a flag
    GET  /ctf/challenge/<id>/hint     - Get next hint (if unlocked)
    POST /ctf/challenge/<id>/hint/unlock - Unlock next hint (costs points)
    GET  /ctf/leaderboard             - Get leaderboard
    GET  /ctf/user/progress           - Get user progress
    GET  /ctf/achievements            - Get user achievements

Authentication:
    Mock authentication using query parameter: ?user_id=<id>
    In production, replace with proper JWT/session authentication

Author: AegisForge CTF Platform
"""

from flask import Blueprint, request, jsonify, current_app
from typing import Dict, Any, Tuple
from functools import wraps
import traceback

from .ctf_manager import CTFManager, Challenge


# Create Blueprint for CTF endpoints
ctf_api = Blueprint('ctf_api', __name__, url_prefix='/ctf')

# Global CTF manager instance (initialized by app)
ctf_manager: CTFManager = None


def init_ctf_api(manager: CTFManager):
    """
    Initialize the CTF API with a CTFManager instance.
    
    This should be called by the Flask app during initialization.
    
    Args:
        manager (CTFManager): Initialized CTF manager instance
    """
    global ctf_manager
    ctf_manager = manager


def get_user_id() -> str:
    """
    Extract user ID from request.
    
    Mock authentication - checks for 'user_id' in query params or JSON body.
    In production, replace this with proper authentication (JWT, sessions, etc.)
    
    Returns:
        str: User identifier
        
    Raises:
        ValueError: If no user_id provided
    """
    # Try query parameter first
    user_id = request.args.get('user_id')
    
    # Try JSON body if POST/PUT request
    if not user_id and request.is_json:
        user_id = request.json.get('user_id')
    
    if not user_id:
        raise ValueError("user_id required (provide as ?user_id=<id> or in JSON body)")
    
    return user_id


def require_auth(f):
    """
    Decorator to require authentication for endpoints.
    
    Extracts user_id and passes it to the wrapped function.
    Returns 401 if authentication fails.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            user_id = get_user_id()
            return f(user_id=user_id, *args, **kwargs)
        except ValueError as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 401
    return decorated_function


def success_response(data: Any, message: str = None, status_code: int = 200) -> Tuple[Dict, int]:
    """
    Create a standardized success response.
    
    Args:
        data: Response data
        message: Optional success message
        status_code: HTTP status code (default: 200)
        
    Returns:
        Tuple[Dict, int]: JSON response and status code
    """
    response = {
        'success': True,
        'data': data
    }
    if message:
        response['message'] = message
    return jsonify(response), status_code


def error_response(error: str, status_code: int = 400, details: Any = None) -> Tuple[Dict, int]:
    """
    Create a standardized error response.
    
    Args:
        error: Error message
        status_code: HTTP status code (default: 400)
        details: Optional additional error details
        
    Returns:
        Tuple[Dict, int]: JSON response and status code
    """
    response = {
        'success': False,
        'error': error
    }
    if details:
        response['details'] = details
    return jsonify(response), status_code


@ctf_api.route('/challenges', methods=['GET'])
def list_challenges():
    """
    Get list of all available CTF challenges.
    
    Query Parameters:
        category (str, optional): Filter by category
        difficulty (str, optional): Filter by difficulty
        
    Returns:
        JSON response with list of challenges
        
    Example:
        GET /ctf/challenges
        GET /ctf/challenges?category=web
        GET /ctf/challenges?difficulty=easy
        
    Response:
        {
            "success": true,
            "data": {
                "challenges": [...],
                "total": 10,
                "filters": {...}
            }
        }
    """
    try:
        # Get all challenges
        challenges = ctf_manager.get_all_challenges()
        
        # Apply filters
        category = request.args.get('category')
        difficulty = request.args.get('difficulty')
        
        if category:
            challenges = [c for c in challenges if c['category'].lower() == category.lower()]
        if difficulty:
            challenges = [c for c in challenges if c['difficulty'].lower() == difficulty.lower()]
        
        return success_response({
            'challenges': challenges,
            'total': len(challenges),
            'filters': {
                'category': category,
                'difficulty': difficulty
            }
        })
    except Exception as e:
        return error_response(f"Failed to list challenges: {str(e)}", 500)


@ctf_api.route('/challenge/<challenge_id>', methods=['GET'])
def get_challenge(challenge_id: str):
    """
    Get detailed information about a specific challenge.
    
    URL Parameters:
        challenge_id (str): Unique challenge identifier
        
    Query Parameters:
        user_id (str, optional): User ID to include user-specific progress
        
    Returns:
        JSON response with challenge details
        
    Example:
        GET /ctf/challenge/web_sqli_1
        GET /ctf/challenge/web_sqli_1?user_id=user123
        
    Response:
        {
            "success": true,
            "data": {
                "challenge": {...},
                "user_progress": {...}  // if user_id provided
            }
        }
    """
    try:
        # Get challenge details
        challenge = ctf_manager.get_challenge(challenge_id)
        
        if not challenge:
            return error_response("Challenge not found", 404)
        
        response_data = {'challenge': challenge}
        
        # Include user progress if authenticated
        try:
            user_id = get_user_id()
            status = ctf_manager.get_challenge_status(challenge_id, user_id)
            response_data['user_progress'] = {
                'state': status['state'],
                'progress': status['progress'],
                'attempts': status['attempts'],
                'hints_unlocked': status['hints_unlocked']
            }
        except ValueError:
            # No user_id provided, skip user progress
            pass
        
        return success_response(response_data)
    except Exception as e:
        return error_response(f"Failed to get challenge: {str(e)}", 500)


@ctf_api.route('/challenge/<challenge_id>/start', methods=['POST'])
@require_auth
def start_challenge(challenge_id: str, user_id: str):
    """
    Start a challenge for the authenticated user.
    
    URL Parameters:
        challenge_id (str): Unique challenge identifier
        
    Query Parameters:
        user_id (str): User identifier (required)
        
    Returns:
        JSON response with challenge start confirmation
        
    Example:
        POST /ctf/challenge/web_sqli_1/start?user_id=user123
        
    Response:
        {
            "success": true,
            "message": "Challenge started successfully",
            "data": {
                "challenge_id": "web_sqli_1",
                "state": "in_progress",
                "started_at": "2024-01-15T10:30:00"
            }
        }
    """
    try:
        success, message, data = ctf_manager.start_challenge(challenge_id, user_id)
        
        if success:
            return success_response(data, message, 201)
        else:
            return error_response(message, 400, data)
    except Exception as e:
        return error_response(f"Failed to start challenge: {str(e)}", 500)


@ctf_api.route('/challenge/<challenge_id>/submit', methods=['POST'])
@require_auth
def submit_flag(challenge_id: str, user_id: str):
    """
    Submit a flag for verification.
    
    URL Parameters:
        challenge_id (str): Unique challenge identifier
        
    Query Parameters:
        user_id (str): User identifier (required)
        
    Request Body (JSON):
        {
            "flag": "HQX{submitted_flag_here}"
        }
        
    Returns:
        JSON response with verification result
        
    Example:
        POST /ctf/challenge/web_sqli_1/submit?user_id=user123
        Body: {"flag": "HQX{admin_password_12345}"}
        
    Response (Correct):
        {
            "success": true,
            "message": "Correct flag! Challenge solved!",
            "data": {
                "correct": true,
                "points_earned": 120,
                "is_first_blood": true,
                "time_taken": "0:15:30",
                "new_achievements": [...]
            }
        }
        
    Response (Incorrect):
        {
            "success": false,
            "error": "Incorrect flag (Attempt 2)",
            "data": {
                "correct": false,
                "attempts": 2
            }
        }
    """
    try:
        # Get flag from request body
        if not request.is_json:
            return error_response("Content-Type must be application/json", 400)
        
        flag = request.json.get('flag')
        if not flag:
            return error_response("'flag' field required in JSON body", 400)
        
        # Submit flag
        correct, message, data = ctf_manager.submit_flag(challenge_id, user_id, flag)
        
        if correct:
            # Correct flag
            return success_response({
                'correct': True,
                **data
            }, message, 200)
        else:
            # Incorrect flag
            return error_response(message, 200, {
                'correct': False,
                **data
            })
    except Exception as e:
        return error_response(f"Failed to submit flag: {str(e)}", 500)


@ctf_api.route('/challenge/<challenge_id>/hint', methods=['GET'])
@require_auth
def get_hint(challenge_id: str, user_id: str):
    """
    Get the next unlocked hint for a challenge.
    
    URL Parameters:
        challenge_id (str): Unique challenge identifier
        
    Query Parameters:
        user_id (str): User identifier (required)
        hint_index (int, optional): Specific hint index (default: next unlocked)
        
    Returns:
        JSON response with hint text or unlock status
        
    Example:
        GET /ctf/challenge/web_sqli_1/hint?user_id=user123
        GET /ctf/challenge/web_sqli_1/hint?user_id=user123&hint_index=0
        
    Response (Hint Available):
        {
            "success": true,
            "data": {
                "hint_index": 0,
                "hint_text": "Check the login form",
                "unlocked": true
            }
        }
        
    Response (Hint Locked):
        {
            "success": false,
            "error": "Hint not unlocked",
            "details": {
                "hint_index": 1,
                "unlocked": false,
                "cost": 20
            }
        }
    """
    try:
        # Get challenge status to determine hints unlocked
        status = ctf_manager.get_challenge_status(challenge_id, user_id)
        
        if 'error' in status:
            return error_response(status['error'], 404)
        
        hints_unlocked = status['hints_unlocked']
        
        # Get hint index from query param or use last unlocked
        hint_index = request.args.get('hint_index', type=int)
        if hint_index is None:
            hint_index = hints_unlocked - 1 if hints_unlocked > 0 else 0
        
        # Get hint
        success, message, hint_text = ctf_manager.get_hint(challenge_id, user_id, hint_index)
        
        if success:
            return success_response({
                'hint_index': hint_index,
                'hint_text': hint_text,
                'unlocked': True
            })
        else:
            # Calculate cost for next hint
            next_hint_index = hints_unlocked
            hint_cost = ctf_manager.hint_system.hint_costs[
                min(next_hint_index, len(ctf_manager.hint_system.hint_costs) - 1)
            ]
            
            return error_response(message, 403, {
                'hint_index': hint_index,
                'unlocked': False,
                'next_hint_cost': hint_cost,
                'hints_unlocked': hints_unlocked
            })
    except Exception as e:
        return error_response(f"Failed to get hint: {str(e)}", 500)


@ctf_api.route('/challenge/<challenge_id>/hint/unlock', methods=['POST'])
@require_auth
def unlock_hint(challenge_id: str, user_id: str):
    """
    Unlock the next hint for a challenge (costs points).
    
    URL Parameters:
        challenge_id (str): Unique challenge identifier
        
    Query Parameters:
        user_id (str): User identifier (required)
        
    Returns:
        JSON response with unlocked hint and cost
        
    Example:
        POST /ctf/challenge/web_sqli_1/hint/unlock?user_id=user123
        
    Response (Success):
        {
            "success": true,
            "message": "Hint unlocked successfully",
            "data": {
                "hint_index": 1,
                "hint_text": "Try SQL injection in username field",
                "cost": 20,
                "hints_unlocked": 2,
                "hints_remaining": 1,
                "points_remaining": 80
            }
        }
        
    Response (Not Enough Points):
        {
            "success": false,
            "error": "Not enough points. Need 20, have 10"
        }
    """
    try:
        success, message, data = ctf_manager.unlock_hint(challenge_id, user_id)
        
        if success:
            return success_response(data, message, 201)
        else:
            return error_response(message, 400, data)
    except Exception as e:
        return error_response(f"Failed to unlock hint: {str(e)}", 500)


@ctf_api.route('/leaderboard', methods=['GET'])
def get_leaderboard():
    """
    Get the current CTF leaderboard.
    
    Query Parameters:
        limit (int, optional): Number of top users (default: 10, max: 100)
        
    Returns:
        JSON response with leaderboard rankings
        
    Example:
        GET /ctf/leaderboard
        GET /ctf/leaderboard?limit=20
        
    Response:
        {
            "success": true,
            "data": {
                "leaderboard": [
                    {
                        "rank": 1,
                        "user_id": "user123",
                        "username": "user123",
                        "points": 450,
                        "solves": 5,
                        "first_bloods": 2
                    },
                    ...
                ],
                "total_users": 50
            }
        }
    """
    try:
        # Get limit from query params (default: 10, max: 100)
        limit = request.args.get('limit', default=10, type=int)
        limit = min(max(1, limit), 100)  # Clamp between 1 and 100
        
        # Get leaderboard
        leaderboard = ctf_manager.get_leaderboard(limit=limit)
        
        return success_response({
            'leaderboard': leaderboard,
            'total_users': len(leaderboard),
            'limit': limit
        })
    except Exception as e:
        return error_response(f"Failed to get leaderboard: {str(e)}", 500)


@ctf_api.route('/user/progress', methods=['GET'])
@require_auth
def get_user_progress(user_id: str):
    """
    Get comprehensive progress for the authenticated user.
    
    Query Parameters:
        user_id (str): User identifier (required)
        
    Returns:
        JSON response with user progress across all challenges
        
    Example:
        GET /ctf/user/progress?user_id=user123
        
    Response:
        {
            "success": true,
            "data": {
                "user_id": "user123",
                "challenges_started": 8,
                "challenges_solved": 5,
                "total_points": 450,
                "total_attempts": 12,
                "stats": {
                    "rank": 3,
                    "solves": 5,
                    "first_bloods": 2,
                    "hints_used": 4
                },
                "challenges": {
                    "web_sqli_1": {
                        "state": "solved",
                        "started_at": "...",
                        "solved_at": "...",
                        ...
                    },
                    ...
                }
            }
        }
    """
    try:
        progress = ctf_manager.get_user_progress(user_id)
        return success_response(progress)
    except Exception as e:
        return error_response(f"Failed to get user progress: {str(e)}", 500)


@ctf_api.route('/achievements', methods=['GET'])
@require_auth
def get_achievements(user_id: str):
    """
    Get achievements for the authenticated user.
    
    Query Parameters:
        user_id (str): User identifier (required)
        
    Returns:
        JSON response with earned and available achievements
        
    Example:
        GET /ctf/achievements?user_id=user123
        
    Response:
        {
            "success": true,
            "data": {
                "user_id": "user123",
                "earned": [
                    {
                        "id": "first_blood",
                        "name": "First Blood",
                        "description": "Be the first to solve a challenge",
                        "category": "special",
                        "icon": "🩸",
                        "points": 50,
                        "earned_at": "2024-01-15T10:45:00"
                    },
                    ...
                ],
                "available": [...],
                "total_earned": 5,
                "total_points": 250
            }
        }
    """
    try:
        achievements = ctf_manager.get_user_achievements(user_id)
        return success_response(achievements)
    except Exception as e:
        return error_response(f"Failed to get achievements: {str(e)}", 500)


@ctf_api.route('/stats', methods=['GET'])
def get_platform_stats():
    """
    Get overall platform statistics.
    
    Returns:
        JSON response with platform-wide stats
        
    Example:
        GET /ctf/stats
        
    Response:
        {
            "success": true,
            "data": {
                "total_challenges": 25,
                "total_users": 150,
                "total_solves": 450,
                "categories": {
                    "web": 10,
                    "crypto": 8,
                    "forensics": 7
                }
            }
        }
    """
    try:
        challenges = ctf_manager.get_all_challenges()
        leaderboard = ctf_manager.get_leaderboard(limit=1000)
        
        # Count by category
        categories = {}
        for c in challenges:
            cat = c['category']
            categories[cat] = categories.get(cat, 0) + 1
        
        # Count total solves
        total_solves = sum(entry['solves'] for entry in leaderboard)
        
        return success_response({
            'total_challenges': len(challenges),
            'total_users': len(leaderboard),
            'total_solves': total_solves,
            'categories': categories
        })
    except Exception as e:
        return error_response(f"Failed to get platform stats: {str(e)}", 500)


@ctf_api.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return error_response("Endpoint not found", 404)


@ctf_api.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return error_response("Internal server error", 500)


def main():
    """Example usage and testing of CTF API endpoints."""
    from flask import Flask
    import json
    
    print("=== AegisForge CTF API - Test Suite ===\n")
    
    # Create Flask app
    app = Flask(__name__)
    app.config['TESTING'] = True
    
    # Initialize CTF Manager with sample data
    manager = CTFManager()
    
    # Add sample challenges
    from .ctf_manager import Challenge
    sample_challenges = [
        Challenge(
            id="web_sqli_1",
            title="SQL Injection Basics",
            description="Find the hidden admin password using SQL injection",
            category="web",
            difficulty="easy",
            points=100,
            flag_template="admin_password_12345",
            hints=[
                "Check the login form for SQL injection vulnerabilities",
                "Try using ' OR '1'='1 in the username field",
                "Look for the admin table in the database"
            ],
            files=["http://challenge.local:8080"],
            tags=["sql", "injection", "web"]
        ),
        Challenge(
            id="crypto_xor_1",
            title="XOR Encryption",
            description="Decrypt the XOR encrypted message",
            category="crypto",
            difficulty="medium",
            points=200,
            flag_template="secret_key_xyz",
            hints=[
                "XOR encryption uses the same key for encryption and decryption",
                "Try common keys like 'A', '0', or single bytes"
            ],
            tags=["xor", "encryption", "crypto"]
        )
    ]
    
    for challenge in sample_challenges:
        manager.challenges[challenge.id] = challenge
    
    # Initialize API
    init_ctf_api(manager)
    app.register_blueprint(ctf_api)
    
    print(f"✓ Initialized CTF API with {len(manager.challenges)} challenges\n")
    
    # Create test client
    client = app.test_client()
    
    # Test 1: List all challenges
    print("Test 1: GET /ctf/challenges")
    response = client.get('/ctf/challenges')
    data = response.get_json()
    print(f"  Status: {response.status_code}")
    print(f"  Challenges: {data['data']['total']}")
    print()
    
    # Test 2: Get specific challenge
    print("Test 2: GET /ctf/challenge/web_sqli_1")
    response = client.get('/ctf/challenge/web_sqli_1')
    data = response.get_json()
    print(f"  Status: {response.status_code}")
    print(f"  Challenge: {data['data']['challenge']['title']}")
    print()
    
    # Test 3: Start challenge (requires auth)
    print("Test 3: POST /ctf/challenge/web_sqli_1/start (with user_id)")
    response = client.post('/ctf/challenge/web_sqli_1/start?user_id=test_user')
    data = response.get_json()
    print(f"  Status: {response.status_code}")
    print(f"  Message: {data.get('message', data.get('error'))}")
    print()
    
    # Test 4: Submit wrong flag
    print("Test 4: POST /ctf/challenge/web_sqli_1/submit (wrong flag)")
    response = client.post(
        '/ctf/challenge/web_sqli_1/submit?user_id=test_user',
        json={'flag': 'HQX{wrong_flag}'},
        content_type='application/json'
    )
    data = response.get_json()
    print(f"  Status: {response.status_code}")
    print(f"  Correct: {data.get('details', {}).get('correct', False)}")
    print()
    
    # Test 5: Submit correct flag
    print("Test 5: POST /ctf/challenge/web_sqli_1/submit (correct flag)")
    correct_flag = manager.flag_generator.generate_user_flag(
        "web_sqli_1", "test_user", "admin_password_12345"
    )
    response = client.post(
        '/ctf/challenge/web_sqli_1/submit?user_id=test_user',
        json={'flag': correct_flag},
        content_type='application/json'
    )
    data = response.get_json()
    print(f"  Status: {response.status_code}")
    print(f"  Correct: {data['data']['correct']}")
    print(f"  Points: {data['data']['points_earned']}")
    print()
    
    # Test 6: Get user progress
    print("Test 6: GET /ctf/user/progress")
    response = client.get('/ctf/user/progress?user_id=test_user')
    data = response.get_json()
    print(f"  Status: {response.status_code}")
    print(f"  Solved: {data['data']['challenges_solved']}")
    print(f"  Points: {data['data']['total_points']}")
    print()
    
    # Test 7: Get leaderboard
    print("Test 7: GET /ctf/leaderboard")
    response = client.get('/ctf/leaderboard?limit=5')
    data = response.get_json()
    print(f"  Status: {response.status_code}")
    print(f"  Users: {data['data']['total_users']}")
    if data['data']['leaderboard']:
        print(f"  Top user: {data['data']['leaderboard'][0]['user_id']} "
              f"({data['data']['leaderboard'][0]['points']} pts)")
    print()
    
    # Test 8: Get platform stats
    print("Test 8: GET /ctf/stats")
    response = client.get('/ctf/stats')
    data = response.get_json()
    print(f"  Status: {response.status_code}")
    print(f"  Total challenges: {data['data']['total_challenges']}")
    print(f"  Total users: {data['data']['total_users']}")
    print(f"  Total solves: {data['data']['total_solves']}")
    print()
    
    # Test 9: Get achievements
    print("Test 9: GET /ctf/achievements")
    response = client.get('/ctf/achievements?user_id=test_user')
    data = response.get_json()
    print(f"  Status: {response.status_code}")
    print(f"  Earned: {data['data']['total_earned']}")
    print()
    
    # Test 10: Error handling - missing auth
    print("Test 10: POST /ctf/challenge/web_sqli_1/start (no user_id)")
    response = client.post('/ctf/challenge/web_sqli_1/start')
    data = response.get_json()
    print(f"  Status: {response.status_code}")
    print(f"  Error: {data['error']}")
    print()
    
    print("=== All API tests completed successfully! ===")


if __name__ == "__main__":
    main()
