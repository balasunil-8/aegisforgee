"""
AegisForge CTF Challenge: Paper Script
Category: Forensics
Difficulty: Advanced (300 points)
Author: AegisForge Team

Challenge Description:
A suspicious PDF was intercepted. It contains hidden JavaScript code.

Flag Format: HQX{...}
"""

import secrets
import json

CHALLENGE_ID = "paper_script"
CHALLENGE_NAME = "Paper Script"
CATEGORY = "forensics"
DIFFICULTY = "advanced"
POINTS = 300

def generate_challenge(user_seed: str = None) -> dict:
    """
    Generate PDF forensics challenge with obfuscated JavaScript
    """
    if user_seed:
        flag = f"HQX{{PDF_j4v45cr1pt_0bfu5c4t10n_{user_seed[:8]}}}"
    else:
        random_suffix = secrets.token_hex(4)
        flag = f"HQX{{PDF_j4v45cr1pt_0bfu5c4t10n_{random_suffix}}}"
    
    # Simulate obfuscated JavaScript that would be embedded in PDF
    # In reality, this would be hex-encoded or otherwise obfuscated
    obfuscated_js = f"""
var _0x4d2e=['\\x48\\x51\\x58\\x7b','{flag[4:-1]}','\\x7d'];
var _0x1a3b=function(_0x4d2e1c,_0x1a3b2d){{return _0x4d2e[_0x4d2e1c-0x0];}};
var flag=_0x1a3b('0x0')+_0x1a3b('0x1')+_0x1a3b('0x2');
// Flag: HQX{{...}}
"""
    
    description = f"""
╔══════════════════════════════════════════════╗
║          PAPER SCRIPT CHALLENGE              ║
╚══════════════════════════════════════════════╝

A suspicious PDF file has been intercepted.
Initial analysis shows it contains JavaScript code.

Filename: suspicious_document.pdf
Size: 247 KB
Created: 2025-12-15

Your task:
1. Extract the JavaScript objects from the PDF
2. De-obfuscate the code
3. Find the hidden flag

Tools you'll need:
- pdf-parser.py (from Didier Stevens)
- pdfid.py
- peepdf
- Manual analysis

The PDF contains hex-encoded strings that form the flag.
"""
    
    pdf_analysis = """
PDF Analysis Output:
===================

$ pdfid suspicious_document.pdf
PDF Header: %PDF-1.4
Objects: 12
/JS: 2 (JavaScript detected!)
/JavaScript: 2
/OpenAction: 1

$ pdf-parser.py --search javascript suspicious_document.pdf
obj 8 0
Type: /Action
/S /JavaScript
/JS (Obfuscated code detected)

$ pdf-parser.py --object 8 --filter suspicious_document.pdf
[Extracted JavaScript - see obfuscated_code.js]
"""
    
    return {
        'challenge_id': CHALLENGE_ID,
        'name': CHALLENGE_NAME,
        'category': CATEGORY,
        'difficulty': DIFFICULTY,
        'points': POINTS,
        'description': 'A suspicious PDF was intercepted. It contains hidden JavaScript code.',
        'flag': flag,
        'artifacts': {
            'challenge_description.txt': description,
            'pdf_analysis.txt': pdf_analysis,
            'obfuscated_code.js': obfuscated_js,
            'hints.txt': """
Hint 1: Use pdf-parser.py to extract JavaScript objects
Hint 2: The \\x indicates hex-encoded characters
Hint 3: Decode the hex values to ASCII
Hint 4: Look for the flag format: HQX{...}
"""
        },
        'hints': [
            {
                'cost': 30,
                'text': 'Use pdf-parser.py to extract JavaScript from the PDF.'
            },
            {
                'cost': 50,
                'text': 'The \\x sequences are hexadecimal character codes.'
            },
            {
                'cost': 70,
                'text': 'Convert hex codes like \\x48 to ASCII: 0x48 = H'
            }
        ],
        'solution': {
            'steps': [
                '1. Identify PDF contains JavaScript with pdfid.py',
                '2. Extract JavaScript with pdf-parser.py',
                '3. Find hex-encoded strings (\\x48\\x51\\x58 = HQX)',
                '4. Decode all hex sequences to reveal flag',
                '5. Reconstruct the complete flag'
            ],
            'tools': ['pdf-parser.py', 'pdfid.py', 'peepdf', 'CyberChef'],
            'command': """
# Extract JavaScript
pdf-parser.py --search javascript suspicious_document.pdf
pdf-parser.py --object 8 --filter suspicious_document.pdf > extracted.js

# Decode hex in Python
data = "\\x48\\x51\\x58\\x7b..."  # Extracted hex
decoded = bytes.fromhex(data.replace('\\x', '')).decode('ascii')
print(decoded)
"""
        }
    }

def verify_flag(submitted_flag: str, correct_flag: str) -> bool:
    """Verify if the submitted flag is correct"""
    return submitted_flag.strip() == correct_flag.strip()

if __name__ == '__main__':
    challenge = generate_challenge("test_user_123")
    print(json.dumps(challenge, indent=2))
