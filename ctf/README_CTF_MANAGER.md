# CTF Manager & API Documentation

## Overview

The CTF Manager system provides comprehensive CTF (Capture The Flag) challenge management with integrated Flask API endpoints.

## Files

### 1. `ctf_manager.py` - Core CTF Management System

**Main Class: `CTFManager`**

Coordinates all CTF operations including:
- Challenge lifecycle management
- User progress tracking
- Flag generation and validation
- Hint system integration
- Leaderboard and scoring
- Achievement tracking

**Key Methods:**

```python
# Challenge Management
get_all_challenges() -> List[Dict]
get_challenge(challenge_id: str) -> Optional[Dict]

# User Operations
start_challenge(challenge_id: str, user_id: str) -> Tuple[bool, str, Optional[Dict]]
submit_flag(challenge_id: str, user_id: str, flag: str) -> Tuple[bool, str, Optional[Dict]]
get_user_progress(user_id: str) -> Dict
get_challenge_status(challenge_id: str, user_id: str) -> Dict

# Hint System
get_hint(challenge_id: str, user_id: str, hint_index: int) -> Tuple[bool, str, Optional[str]]
unlock_hint(challenge_id: str, user_id: str) -> Tuple[bool, str, Optional[Dict]]

# Leaderboard & Achievements
get_leaderboard(limit: int = 10) -> List[Dict]
get_user_achievements(user_id: str) -> Dict
```

**Challenge States:**
- `NOT_STARTED` - User hasn't started the challenge
- `IN_PROGRESS` - User has started but not solved
- `SOLVED` - User has successfully solved

### 2. `ctf_api.py` - Flask REST API Endpoints

**Blueprint: `ctf_api`** (prefix: `/ctf`)

**Endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ctf/challenges` | List all challenges |
| GET | `/ctf/challenge/<id>` | Get challenge details |
| POST | `/ctf/challenge/<id>/start` | Start a challenge |
| POST | `/ctf/challenge/<id>/submit` | Submit a flag |
| GET | `/ctf/challenge/<id>/hint` | Get hint (if unlocked) |
| POST | `/ctf/challenge/<id>/hint/unlock` | Unlock next hint |
| GET | `/ctf/leaderboard` | Get leaderboard rankings |
| GET | `/ctf/user/progress` | Get user progress |
| GET | `/ctf/achievements` | Get user achievements |
| GET | `/ctf/stats` | Get platform statistics |

**Authentication:**

Currently uses mock authentication via `user_id` parameter:
- Query parameter: `?user_id=user123`
- JSON body: `{"user_id": "user123"}`

Replace with proper JWT/session authentication in production.

## Usage Examples

### Basic Setup

```python
from ctf.ctf_manager import CTFManager, Challenge
from ctf.ctf_api import init_ctf_api, ctf_api
from flask import Flask

# Create Flask app
app = Flask(__name__)

# Initialize CTF Manager
manager = CTFManager(
    challenges_file='challenges.json',
    hints_file='hints.json',
    secret_key='your-secret-key'
)

# Initialize and register API
init_ctf_api(manager)
app.register_blueprint(ctf_api)

# Run app
app.run(debug=True)
```

### API Request Examples

**List Challenges:**
```bash
curl http://localhost:5000/ctf/challenges
```

**Start Challenge:**
```bash
curl -X POST "http://localhost:5000/ctf/challenge/web_sqli_1/start?user_id=user123"
```

**Submit Flag:**
```bash
curl -X POST "http://localhost:5000/ctf/challenge/web_sqli_1/submit?user_id=user123" \
  -H "Content-Type: application/json" \
  -d '{"flag": "HQX{admin_password_12345_abc123}"}'
```

**Get User Progress:**
```bash
curl "http://localhost:5000/ctf/user/progress?user_id=user123"
```

**Unlock Hint:**
```bash
curl -X POST "http://localhost:5000/ctf/challenge/web_sqli_1/hint/unlock?user_id=user123"
```

### Response Format

**Success Response:**
```json
{
  "success": true,
  "message": "Operation successful",
  "data": { ... }
}
```

**Error Response:**
```json
{
  "success": false,
  "error": "Error message",
  "details": { ... }
}
```

## Integration with Existing Systems

The CTF Manager integrates with:

1. **FlagGenerator** (`flag_generator.py`) - Dynamic flag generation
2. **HintSystem** (`hint_system.py`) - Progressive hint management
3. **Leaderboard** (`leaderboard.py`) - Scoring and rankings
4. **AchievementSystem** (`achievements.py`) - Achievement tracking

## Testing

Both files include comprehensive test suites:

```bash
# Test CTF Manager
python -m ctf.ctf_manager

# Test CTF API
python -m ctf.ctf_api
```

## Challenge JSON Format

```json
[
  {
    "id": "web_sqli_1",
    "title": "SQL Injection Basics",
    "description": "Find the hidden admin password",
    "category": "web",
    "difficulty": "easy",
    "points": 100,
    "flag_template": "admin_password_12345",
    "hints": [
      "Check the login form",
      "Try SQL injection"
    ],
    "files": ["http://challenge.local:8080"],
    "tags": ["sql", "injection", "web"]
  }
]
```

## Security Notes

1. **Authentication:** Replace mock authentication with proper JWT/session auth
2. **Rate Limiting:** Add rate limiting to prevent brute force attacks
3. **Input Validation:** All user inputs are validated
4. **Flag Security:** Flags are generated deterministically per user
5. **CORS:** Configure CORS appropriately for your deployment

## Features

- ✅ User-specific dynamic flags
- ✅ Progressive hint system with point costs
- ✅ Real-time leaderboard
- ✅ First blood bonuses
- ✅ Achievement system
- ✅ Challenge state tracking
- ✅ Comprehensive error handling
- ✅ RESTful API design
- ✅ Professional documentation
- ✅ Test suites included

## Future Enhancements

- Team-based competitions
- Time-limited challenges
- Challenge categories and filters
- User profiles and statistics
- WebSocket for real-time updates
- Challenge difficulty ratings
- Multi-language support

