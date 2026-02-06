"""
AegisForge CTF Challenge: SmallE
Category: Cryptography
Difficulty: Intermediate (100 points)
Author: AegisForge Team

Challenge Description:
An intercepted RSA encrypted message. The encryption key seems weak...

Flag Format: HQX{...}
"""

import secrets
import json
from math import isqrt

CHALLENGE_ID = "smalle"
CHALLENGE_NAME = "SmallE"
CATEGORY = "crypto"
DIFFICULTY = "intermediate"
POINTS = 100

def generate_challenge(user_seed: str = None) -> dict:
    """
    Generate RSA challenge with small exponent (e=3)
    This is vulnerable to cube root attack when m^3 < n
    """
    if user_seed:
        flag = f"HQX{{sm4ll_3xp0n3nt_w34k_{user_seed[:8]}}}"
    else:
        random_suffix = secrets.token_hex(4)
        flag = f"HQX{{sm4ll_3xp0n3nt_w34k_{random_suffix}}}"
    
    # Convert flag to integer
    m = int.from_bytes(flag.encode(), 'big')
    
    # Small exponent e=3
    e = 3
    
    # For this educational example, we use a modulus larger than m^3
    # But still demonstrate the vulnerability
    n = 0x9c7b8e6a1f3d2c5b4a9e8d7c6f5e4d3c2b1a9e8d7c6f5e4d3c2b1a9e8d7c6f5e4d3c2b1a
    
    # Encrypt: c = m^e mod n
    # Since m^3 < n, we can just compute m^3
    ct = pow(m, e)
    
    artifact = f"""
╔══════════════════════════════════════════════╗
║          RSA ENCRYPTED MESSAGE               ║
╚══════════════════════════════════════════════╝

Intercepted RSA parameters:

n (modulus):
{hex(n)}

e (public exponent):
{e}

ct (ciphertext):
{hex(ct)}

The message is encrypted using textbook RSA.
Can you recover the plaintext?
"""
    
    return {
        'challenge_id': CHALLENGE_ID,
        'name': CHALLENGE_NAME,
        'category': CATEGORY,
        'difficulty': DIFFICULTY,
        'points': POINTS,
        'description': 'An intercepted RSA encrypted message. The encryption key seems weak...',
        'flag': flag,
        'artifacts': {
            'encrypted_message.txt': artifact,
            'parameters.json': json.dumps({
                'n': hex(n),
                'e': e,
                'ct': hex(ct)
            }, indent=2)
        },
        'hints': [
            {
                'cost': 15,
                'text': 'The exponent e=3 is very small. What does that mean?'
            },
            {
                'cost': 25,
                'text': 'When e=3 and m^3 < n, no modular reduction occurs.'
            },
            {
                'cost': 40,
                'text': 'Compute the integer cube root of the ciphertext.'
            }
        ],
        'solution': {
            'steps': [
                '1. Recognize that e=3 is a small exponent',
                '2. Check if m^3 < n (likely true for small messages)',
                '3. Compute integer cube root of ciphertext',
                '4. Convert integer back to string to get flag'
            ],
            'tools': ['Python', 'gmpy2', 'RsaCtfTool'],
            'code': """
import gmpy2

# Given values
ct = """ + hex(ct) + """
e = 3

# Compute cube root
m = gmpy2.iroot(ct, e)[0]

# Convert to string
flag = int(m).to_bytes((int(m).bit_length() + 7) // 8, 'big').decode()
print(flag)
"""
        }
    }

def verify_flag(submitted_flag: str, correct_flag: str) -> bool:
    """Verify if the submitted flag is correct"""
    return submitted_flag.strip() == correct_flag.strip()

if __name__ == '__main__':
    challenge = generate_challenge("test_user_123")
    print(json.dumps(challenge, indent=2))
