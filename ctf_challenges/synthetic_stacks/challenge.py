"""
AegisForge CTF Challenge: Synthetic Stacks
Category: Forensics
Difficulty: Advanced (300 points)
Author: AegisForge Team

Challenge Description:
Multiple layers of obfuscation hide the flag. Peel them back one by one.

Flag Format: HQX{...}
"""

import secrets
import json
import base64

CHALLENGE_ID = "synthetic_stacks"
CHALLENGE_NAME = "Synthetic Stacks"
CATEGORY = "forensics"
DIFFICULTY = "advanced"
POINTS = 300

def generate_challenge(user_seed: str = None) -> dict:
    """
    Generate multi-layer forensics challenge
    Layers: fake extension -> archive -> password -> base64 -> QR code
    """
    if user_seed:
        flag = f"HQX{{mult1_l4y3r_f0r3ns1cs_{user_seed[:8]}}}"
    else:
        random_suffix = secrets.token_hex(4)
        flag = f"HQX{{mult1_l4y3r_f0r3ns1cs_{random_suffix}}}"
    
    # For educational purposes, show the layer structure
    description = f"""
╔══════════════════════════════════════════════╗
║        SYNTHETIC STACKS CHALLENGE            ║
╚══════════════════════════════════════════════╝

You've found a mysterious file: image.png
But is it really an image?

File structure (layers to uncover):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Layer 1: Fake .png extension
         → Actually a 7-Zip archive

Layer 2: Password-protected archive
         → Password: "synthetic"

Layer 3: Contains file "hq.txt"
         → Base64 encoded data

Layer 4: Decoded data is a QR code (PNG)
         → Scan to reveal flag

Layer 5: QR code contains the flag!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Tools needed:
- file command (to identify real file type)
- 7z or 7-Zip (to extract archive)
- base64 (to decode)
- zbarimg or QR scanner (to read QR code)

For this simulation:
Flag: {flag}
"""
    
    solution_guide = """
SOLUTION WALKTHROUGH
===================

Step 1: Identify Real File Type
$ file image.png
image.png: 7-zip archive data

Step 2: Extract Archive (needs password)
$ 7z x image.png
Enter password: synthetic

Extracted files:
- hq.txt

Step 3: Examine hq.txt
$ cat hq.txt
aVZCT1J3MEtHZ29BQUFBTlNVaEVVZ0FBQUFBQUFBQ...
(Base64 encoded PNG data)

Step 4: Decode Base64
$ base64 -d hq.txt > qr_code.png

Step 5: Scan QR Code
$ zbarimg qr_code.png
QR-Code:HQX{mult1_l4y3r_f0r3ns1cs_...}

Or use an online QR reader, smartphone app, or:
$ python3 -c "from pyzbar.pyzbar import decode; from PIL import Image; print(decode(Image.open('qr_code.png'))[0].data.decode())"
"""
    
    return {
        'challenge_id': CHALLENGE_ID,
        'name': CHALLENGE_NAME,
        'category': CATEGORY,
        'difficulty': DIFFICULTY,
        'points': POINTS,
        'description': 'Multiple layers of obfuscation hide the flag. Peel them back one by one.',
        'flag': flag,
        'artifacts': {
            'challenge_description.txt': description,
            'solution_guide.txt': solution_guide,
            'layer_structure.txt': """
Layer Structure:
===============

1. Fake Extension
   File: image.png
   Real Type: 7-Zip archive
   Tool: `file` command

2. Password Protection
   Archive: 7z
   Password: synthetic
   Common passwords to try: password, 123456, synthetic

3. Base64 Encoding
   File: hq.txt
   Content: Base64 encoded data
   Decode: `base64 -d hq.txt > output.png`

4. QR Code
   File: output.png (after decode)
   Contains: The flag
   Read with: zbarimg, smartphone, online reader

5. Flag Retrieved!
   Format: HQX{...}
"""
        },
        'hints': [
            {
                'cost': 40,
                'text': 'Use the `file` command to identify the real file type.'
            },
            {
                'cost': 60,
                'text': 'Try common passwords: password, 123456, synthetic, admin'
            },
            {
                'cost': 80,
                'text': 'The extracted file contains Base64 data. Decode it.'
            },
            {
                'cost': 100,
                'text': 'The decoded data is a QR code image. Scan it.'
            }
        ],
        'solution': {
            'steps': [
                '1. Check file type with `file` command → 7-Zip archive',
                '2. Extract with password "synthetic"',
                '3. Decode Base64 content from hq.txt',
                '4. Scan resulting QR code image',
                '5. Submit the flag from QR code'
            ],
            'tools': ['file', '7z', 'base64', 'zbarimg', 'Python PIL'],
            'commands': [
                'file image.png',
                '7z x image.png  # password: synthetic',
                'base64 -d hq.txt > qr_code.png',
                'zbarimg qr_code.png'
            ]
        }
    }

def verify_flag(submitted_flag: str, correct_flag: str) -> bool:
    """Verify if the submitted flag is correct"""
    return submitted_flag.strip() == correct_flag.strip()

if __name__ == '__main__':
    challenge = generate_challenge("test_user_123")
    print(json.dumps(challenge, indent=2))
