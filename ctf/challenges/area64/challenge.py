#!/usr/bin/env python3
"""
AREA64 - Base64 Encoding CTF Challenge

This challenge teaches beginners about Base64 encoding and the difference
between encoding and encryption. The flag is encoded using Base64, and
players must decode it to capture the flag.

Author: AegisForge Security Team
Category: Cryptography
Difficulty: Beginner
Points: 100
"""

import base64
import os
import json
from datetime import datetime


class Area64Challenge:
    """
    AREA64 CTF Challenge - Base64 Encoding
    
    This class handles the generation and verification of the AREA64 challenge,
    which focuses on teaching Base64 encoding/decoding.
    """
    
    def __init__(self):
        """Initialize the challenge with metadata."""
        self.challenge_id = "area64"
        self.name = "AREA64"
        self.category = "Cryptography"
        self.difficulty = "Beginner"
        self.points = 100
        self.flag = "HQX{b4s364_1s_n0t_encrypti0n_64c0d3}"
        
    def generate_challenge(self):
        """
        Generate the challenge files including the encoded message.
        
        Returns:
            dict: Contains the encoded flag and challenge artifacts
        """
        # Encode the flag using Base64
        encoded_flag = base64.b64encode(self.flag.encode()).decode()
        
        # Create the intercepted message content
        message_content = self._create_intercepted_message(encoded_flag)
        
        # Create instructions
        instructions = self._create_instructions()
        
        return {
            "encoded_flag": encoded_flag,
            "message_content": message_content,
            "instructions": instructions,
            "flag": self.flag
        }
    
    def _create_intercepted_message(self, encoded_flag):
        """
        Create a professional-looking intercepted message document.
        
        Args:
            encoded_flag (str): The Base64 encoded flag
            
        Returns:
            str: Formatted intercepted message
        """
        message = f"""
╔══════════════════════════════════════════════════════════════════╗
║            CLASSIFIED - INTELLIGENCE INTERCEPT                   ║
║                   AREA 64 FACILITY                              ║
╚══════════════════════════════════════════════════════════════════╝

INTERCEPT DATE: 2024-01-15 03:42:17 UTC
FACILITY CODE: AREA-64-ALPHA
CLASSIFICATION: RESTRICTED
SIGNAL SOURCE: 37.2350° N, 115.8111° W

-------------------------------------------------------------------

MESSAGE INTERCEPT BEGIN:

From: Area64_SecOps@classified.mil
To: Field_Agent_7734@classified.mil
Subject: Access Credentials - Project Cipher

Agent 7734,

Your access credentials for the Area 64 facility have been encoded
using our standard protocol. As you know, everything in Area 64
follows "the protocol."

Your encoded access key is:

{encoded_flag}

Please decode this using the standard Area 64 method and present
it at the security checkpoint. Remember: Area 64's encoding is
simple by design - we don't need encryption for internal messages,
just a way to prevent casual observation.

The name "Area 64" should give you a hint about our encoding method.

Best regards,
Area 64 Security Operations

-------------------------------------------------------------------

MESSAGE INTERCEPT END

ANALYST NOTES:
- Message appears to be encoded, not encrypted
- Reference to "Area 64" appears multiple times
- Sender mentions "standard protocol" and "simple by design"
- Encoding method likely indicated by facility name
- No encryption detected - appears to be basic encoding

PRIORITY: Medium
ACTION REQUIRED: Decode message and extract access credentials
"""
        return message.strip()
    
    def _create_instructions(self):
        """
        Create clear instructions for the challenge.
        
        Returns:
            str: Formatted instructions
        """
        instructions = """
CHALLENGE INSTRUCTIONS
======================

OBJECTIVE:
Decode the intercepted message from Area 64 and find the hidden flag.

BACKGROUND:
You've intercepted a message from a mysterious facility called "Area 64".
The message contains an encoded access key that you need to decode.

KEY OBSERVATIONS:
1. The facility is called "Area 64" - this is your biggest clue!
2. The message mentions "encoding" not "encryption" - there's a difference
3. The sender says the method is "simple by design"
4. No complex encryption keys are mentioned

YOUR TASK:
1. Examine the encoded_message.txt file
2. Identify the encoding method used (hint: look at the challenge name!)
3. Decode the encoded string
4. Submit the flag in the format HQX{...}

LEARNING GOALS:
- Understand the difference between encoding and encryption
- Learn about Base64 encoding
- Practice using decoding tools

TOOLS YOU CAN USE:
- Command line: base64, echo, cat
- Python: base64 module
- Online tools: base64decode.org, etc.

Remember: Think about what "64" might mean in the context of encoding!

Good luck!
"""
        return instructions.strip()
    
    def verify_flag(self, submitted_flag):
        """
        Verify if the submitted flag is correct.
        
        Args:
            submitted_flag (str): The flag submitted by the player
            
        Returns:
            bool: True if flag is correct, False otherwise
        """
        # Remove any whitespace and make comparison case-sensitive
        submitted_flag = submitted_flag.strip()
        return submitted_flag == self.flag
    
    def save_challenge_files(self, output_dir="./"):
        """
        Save all challenge files to the specified directory.
        
        Args:
            output_dir (str): Directory to save challenge files
        """
        # Generate challenge content
        challenge_data = self.generate_challenge()
        
        # Create directory structure
        artifacts_dir = os.path.join(output_dir, "artifacts")
        os.makedirs(artifacts_dir, exist_ok=True)
        
        # Save encoded message
        message_path = os.path.join(artifacts_dir, "encoded_message.txt")
        with open(message_path, 'w') as f:
            f.write(challenge_data['message_content'])
        print(f"✓ Created: {message_path}")
        
        # Save instructions
        instructions_path = os.path.join(artifacts_dir, "instructions.txt")
        with open(instructions_path, 'w') as f:
            f.write(challenge_data['instructions'])
        print(f"✓ Created: {instructions_path}")
        
        # Save challenge metadata
        metadata = {
            "challenge_id": self.challenge_id,
            "name": self.name,
            "category": self.category,
            "difficulty": self.difficulty,
            "points": self.points,
            "encoded_flag": challenge_data['encoded_flag'],
            "generated_at": datetime.now().isoformat()
        }
        
        metadata_path = os.path.join(output_dir, "challenge_metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"✓ Created: {metadata_path}")
        
        print(f"\n✅ Challenge files generated successfully!")
        print(f"📝 Flag: {self.flag}")
        print(f"🔐 Encoded: {challenge_data['encoded_flag']}")


def main():
    """
    Main function to demonstrate challenge generation and usage.
    """
    print("=" * 70)
    print("AREA64 - Base64 Encoding Challenge Generator")
    print("=" * 70)
    print()
    
    # Create challenge instance
    challenge = Area64Challenge()
    
    # Generate and save challenge files
    challenge.save_challenge_files()
    
    print("\n" + "=" * 70)
    print("CHALLENGE READY!")
    print("=" * 70)
    print(f"\nChallenge Name: {challenge.name}")
    print(f"Category: {challenge.category}")
    print(f"Difficulty: {challenge.difficulty}")
    print(f"Points: {challenge.points}")
    print("\nFiles created in 'artifacts/' directory")
    print("\nPlayers should:")
    print("  1. Read encoded_message.txt")
    print("  2. Identify the encoding method")
    print("  3. Decode the message")
    print("  4. Submit the flag")


if __name__ == "__main__":
    main()
