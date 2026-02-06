#!/usr/bin/env python3
"""
SMALLE Challenge - Quick Demo
Demonstrates the complete attack flow in a simple way
"""

import gmpy2
from Crypto.Util.number import bytes_to_long, long_to_bytes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def demo_attack():
    """Demonstrate the RSA small exponent attack."""
    
    print("=" * 70)
    print("SMALLE - RSA Small Exponent Attack Demo")
    print("=" * 70)
    
    # Step 1: Load public key
    print("\n[Step 1] Loading public key...")
    with open('artifacts/public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    
    e = public_key.public_numbers().e
    n = public_key.public_numbers().n
    print(f"  - Public exponent (e): {e}")
    print(f"  - Key size: {public_key.key_size} bits")
    
    # Step 2: Load ciphertext
    print("\n[Step 2] Loading encrypted flag...")
    with open('artifacts/encrypted_flag.txt', 'r') as f:
        content = f.read()
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if 'Encrypted Data (hexadecimal):' in line:
                hex_ciphertext = lines[i + 2].strip()
                break
    
    c = int(hex_ciphertext, 16)
    print(f"  - Ciphertext loaded: {len(hex_ciphertext)} hex characters")
    
    # Step 3: Check vulnerability
    print("\n[Step 3] Analyzing vulnerability...")
    if e == 3:
        print(f"  ✓ Small exponent detected (e={e})")
        print(f"  ✓ This is vulnerable to cube root attack!")
    
    # Step 4: Perform attack
    print("\n[Step 4] Performing cube root attack...")
    print(f"  - Computing: m = ∛c")
    
    m, is_exact = gmpy2.iroot(c, e)
    
    if is_exact:
        print(f"  ✓ Exact cube root found!")
    
    # Step 5: Verify
    print("\n[Step 5] Verifying result...")
    if pow(int(m), e) == c:
        print(f"  ✓ Verification passed: m³ = c")
    
    # Step 6: Decode flag
    print("\n[Step 6] Decoding flag...")
    flag = long_to_bytes(int(m)).decode()
    
    print("\n" + "=" * 70)
    print("🎉 ATTACK SUCCESSFUL!")
    print("=" * 70)
    print(f"\n  FLAG: {flag}\n")
    
    # Explanation
    print("=" * 70)
    print("Why did this work?")
    print("=" * 70)
    print("""
In RSA, encryption is: c = m^e mod n

When e=3 (small) and the message m is short:
  • m³ is still smaller than n
  • The modular reduction doesn't happen
  • So: c = m³ mod n = m³ (plain cubing!)
  
To decrypt: m = ∛c (just take the cube root!)

No need to:
  ❌ Factor the modulus n
  ❌ Find the private key d
  ❌ Break RSA's hardness

This is why:
  ✓ Always use e=65537 (standard)
  ✓ Always use proper padding (OAEP)
  ✓ Never use "textbook RSA"
""")
    print("=" * 70)

if __name__ == '__main__':
    try:
        demo_attack()
    except FileNotFoundError as e:
        print(f"Error: Make sure you're in the challenge directory")
        print(f"Run: cd ctf/challenges/smalle/")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
