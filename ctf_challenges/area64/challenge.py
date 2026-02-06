"""
AegisForge CTF Challenge: AREA64
Category: Cryptography
Difficulty: Beginner (100 points)
Author: AegisForge Team

Challenge Description:
To get inside Area 64, you need a key. Look around carefully.

Flag Format: HQX{...}
"""

import base64
import secrets
import json
from pathlib import Path

CHALLENGE_ID = "area64"
CHALLENGE_NAME = "AREA64"
CATEGORY = "crypto"
DIFFICULTY = "beginner"
POINTS = 100

def generate_challenge(user_seed: str = None) -> dict:
    """
    Generate a unique challenge instance for a user
    
    Args:
        user_seed: Optional seed for deterministic generation
    
    Returns:
        dict with challenge metadata and artifacts
    """
    # Generate a unique flag based on user seed
    if user_seed:
        flag = f"HQX{{b4s364_1s_n0t_encrypti0n_{user_seed[:8]}}}"
    else:
        random_suffix = secrets.token_hex(4)
        flag = f"HQX{{b4s364_1s_n0t_encrypti0n_{random_suffix}}}"
    
    # Encode the flag in base64
    encoded_flag = base64.b64encode(flag.encode()).decode()
    
    # Create the artifact file content
    artifact = f"""
╔══════════════════════════════════════════════╗
║          AREA 64 ACCESS TERMINAL             ║
║                                              ║
║  Authorization Key Required                  ║
║                                              ║
║  Encrypted Key:                              ║
║  {encoded_flag}                              ║
║                                              ║
║  Hint: Not everything that looks complex     ║
║        is actually complex.                  ║
╚══════════════════════════════════════════════╝
"""
    
    return {
        'challenge_id': CHALLENGE_ID,
        'name': CHALLENGE_NAME,
        'category': CATEGORY,
        'difficulty': DIFFICULTY,
        'points': POINTS,
        'description': 'To get inside Area 64, you need a key. Look around carefully.',
        'flag': flag,
        'artifacts': {
            'access_terminal.txt': artifact
        },
        'hints': [
            {
                'cost': 10,
                'text': 'The number in the name might be significant.'
            },
            {
                'cost': 20,
                'text': 'Base64 is an encoding scheme, not encryption.'
            },
            {
                'cost': 30,
                'text': 'Use: echo "encoded_string" | base64 -d'
            }
        ],
        'solution': {
            'steps': [
                '1. Notice the challenge name contains "64"',
                '2. Recognize the encoded string as Base64',
                '3. Decode the Base64 string',
                '4. Submit the decoded flag'
            ],
            'tools': ['base64', 'CyberChef', 'Online Base64 decoder'],
            'command': f'echo "{encoded_flag}" | base64 -d'
        }
    }

def verify_flag(submitted_flag: str, correct_flag: str) -> bool:
    """Verify if the submitted flag is correct"""
    return submitted_flag.strip() == correct_flag.strip()

if __name__ == '__main__':
    challenge = generate_challenge("test_user_123")
    print(json.dumps(challenge, indent=2))
