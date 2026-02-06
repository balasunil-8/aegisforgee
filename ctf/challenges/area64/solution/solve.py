#!/usr/bin/env python3
"""
AREA64 Challenge - Automated Solver Script

This script automatically solves the AREA64 challenge by:
1. Reading the encoded message file
2. Extracting the Base64 encoded string
3. Decoding it to reveal the flag
4. Verifying the flag format

Author: AegisForge Security Team
"""

import base64
import re
import os


def read_encoded_message(filepath):
    """
    Read the encoded message from the challenge file.
    
    Args:
        filepath (str): Path to the encoded_message.txt file
        
    Returns:
        str: The Base64 encoded string
    """
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Extract the Base64 encoded string
        # Look for a line with only Base64 characters
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            # Base64 pattern: only letters, numbers, +, /, and = for padding
            if line and re.match(r'^[A-Za-z0-9+/]+=*$', line) and len(line) > 20:
                return line
        
        return None
    except FileNotFoundError:
        print(f"❌ Error: Could not find file: {filepath}")
        return None


def decode_base64(encoded_string):
    """
    Decode a Base64 encoded string.
    
    Args:
        encoded_string (str): The Base64 encoded string
        
    Returns:
        str: The decoded string, or None if decoding fails
    """
    try:
        # Decode from Base64
        decoded_bytes = base64.b64decode(encoded_string)
        decoded_string = decoded_bytes.decode('utf-8')
        return decoded_string
    except Exception as e:
        print(f"❌ Error decoding Base64: {e}")
        return None


def verify_flag(flag):
    """
    Verify that the decoded string matches the flag format.
    
    Args:
        flag (str): The decoded flag
        
    Returns:
        bool: True if flag format is correct
    """
    # Check if flag starts with HQX{ and ends with }
    flag_pattern = r'^HQX\{[^}]+\}$'
    return re.match(flag_pattern, flag) is not None


def main():
    """
    Main solver function.
    """
    print("=" * 70)
    print("AREA64 Challenge - Automated Solver")
    print("=" * 70)
    print()
    
    # Step 1: Find the encoded message file
    print("📁 Step 1: Locating encoded message file...")
    
    # Try multiple possible paths
    possible_paths = [
        "../artifacts/encoded_message.txt",
        "artifacts/encoded_message.txt",
        "./encoded_message.txt"
    ]
    
    encoded_message_path = None
    for path in possible_paths:
        if os.path.exists(path):
            encoded_message_path = path
            break
    
    if not encoded_message_path:
        print("❌ Could not find encoded_message.txt")
        print("   Make sure you're running this from the challenge directory")
        return
    
    print(f"✓ Found: {encoded_message_path}")
    print()
    
    # Step 2: Read and extract the encoded string
    print("🔍 Step 2: Extracting encoded string...")
    encoded_string = read_encoded_message(encoded_message_path)
    
    if not encoded_string:
        print("❌ Could not extract Base64 encoded string from message")
        return
    
    print(f"✓ Extracted: {encoded_string}")
    print()
    
    # Step 3: Decode the Base64 string
    print("🔓 Step 3: Decoding Base64...")
    decoded_flag = decode_base64(encoded_string)
    
    if not decoded_flag:
        print("❌ Failed to decode Base64 string")
        return
    
    print(f"✓ Decoded successfully!")
    print()
    
    # Step 4: Verify flag format
    print("✅ Step 4: Verifying flag...")
    if verify_flag(decoded_flag):
        print("✓ Flag format is correct!")
    else:
        print("⚠️  Warning: Decoded string doesn't match expected flag format")
    
    print()
    print("=" * 70)
    print("🎉 CHALLENGE SOLVED! 🎉")
    print("=" * 70)
    print()
    print(f"🚩 FLAG: {decoded_flag}")
    print()
    print("=" * 70)
    print()
    
    # Educational information
    print("📚 What just happened?")
    print()
    print("1. We read the intercepted message file")
    print("2. We extracted the Base64 encoded string")
    print("3. We decoded it using Python's base64 module")
    print("4. We verified the flag format")
    print()
    print("Key Lesson: Base64 is ENCODING, not ENCRYPTION!")
    print("Anyone can decode it - no secret key needed!")
    print()
    print("Try it yourself in the terminal:")
    print(f'  echo "{encoded_string}" | base64 -d')
    print()


if __name__ == "__main__":
    main()
