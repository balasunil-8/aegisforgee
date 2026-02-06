"""
AegisForge CTF Challenge: Hidden Layers
Category: Steganography
Difficulty: Intermediate (100 points)
Author: AegisForge Team

Challenge Description:
The image looks normal, but something is hidden in the pixels...

Flag Format: HQX{...}
"""

import secrets
import json
from pathlib import Path

CHALLENGE_ID = "hidden_layers"
CHALLENGE_NAME = "Hidden Layers"
CATEGORY = "steganography"
DIFFICULTY = "intermediate"
POINTS = 100

def generate_challenge(user_seed: str = None) -> dict:
    """
    Generate LSB steganography challenge
    In a real implementation, this would create an actual PNG image
    For this educational version, we provide instructions
    """
    if user_seed:
        flag = f"HQX{{LSB_st3g4n0gr4phy_{user_seed[:8]}}}"
    else:
        random_suffix = secrets.token_hex(4)
        flag = f"HQX{{LSB_st3g4n0gr4phy_{random_suffix}}}"
    
    # Simulate LSB encoding instruction
    description = f"""
╔══════════════════════════════════════════════╗
║          HIDDEN LAYERS CHALLENGE             ║
╚══════════════════════════════════════════════╝

You've been provided with an image: hidden.png

The image appears normal, but data is hidden in the 
least significant bits (LSB) of the RGB values.

The flag is encoded in the first 500 pixels, reading
from top-left to bottom-right, using the blue channel.

Tools you might need:
- StegOnline (online tool)
- stegsolve (Java tool)
- Custom Python script with PIL

Hint: Extract LSB from blue channel of first 500 pixels.

For this simulation, the flag is: {flag}
(In a real CTF, you'd need to extract it from the image)
"""
    
    return {
        'challenge_id': CHALLENGE_ID,
        'name': CHALLENGE_NAME,
        'category': CATEGORY,
        'difficulty': DIFFICULTY,
        'points': POINTS,
        'description': 'The image looks normal, but something is hidden in the pixels...',
        'flag': flag,
        'artifacts': {
            'challenge_description.txt': description,
            'instructions.txt': """
LSB Steganography Extraction Guide:

Method 1 - Using StegOnline:
1. Go to https://stegonline.georgeom.net/upload
2. Upload the image
3. Go to "Extract Data" > "Extract"
4. Select "Blue" channel, LSB
5. Look for readable text

Method 2 - Using Python:
```python
from PIL import Image

img = Image.open('hidden.png')
pixels = list(img.getdata())

bits = []
for i in range(500):  # First 500 pixels
    r, g, b = pixels[i]
    bits.append(b & 1)  # Extract LSB from blue channel

# Convert bits to bytes
bytes_data = []
for i in range(0, len(bits), 8):
    byte = 0
    for j in range(8):
        if i + j < len(bits):
            byte = (byte << 1) | bits[i + j]
    bytes_data.append(byte)

flag = bytes(bytes_data).decode('ascii', errors='ignore')
print(flag)
```
"""
        },
        'hints': [
            {
                'cost': 15,
                'text': 'Focus on the blue channel of the image.'
            },
            {
                'cost': 25,
                'text': 'Extract the Least Significant Bit (LSB) from each pixel.'
            },
            {
                'cost': 40,
                'text': 'Convert the extracted bits to ASCII characters.'
            }
        ],
        'solution': {
            'steps': [
                '1. Open image in steganography tool',
                '2. Extract LSB from blue channel',
                '3. Convert bits to text',
                '4. Find the flag in the extracted data'
            ],
            'tools': ['StegOnline', 'stegsolve', 'Python PIL', 'zsteg']
        }
    }

def verify_flag(submitted_flag: str, correct_flag: str) -> bool:
    """Verify if the submitted flag is correct"""
    return submitted_flag.strip() == correct_flag.strip()

if __name__ == '__main__':
    challenge = generate_challenge("test_user_123")
    print(json.dumps(challenge, indent=2))
