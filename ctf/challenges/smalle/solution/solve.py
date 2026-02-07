#!/usr/bin/env python3
"""
SMALLE CTF Challenge - Automated Solver
Demonstrates the cube root attack on RSA with small exponent (e=3)
"""

import os
import sys
import gmpy2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def load_public_key(key_path):
    """
    Load and analyze the RSA public key.
    
    Args:
        key_path: Path to the public key PEM file
    
    Returns:
        tuple: (n, e) from the public key
    """
    print("[*] Loading public key...")
    try:
        with open(key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        public_numbers = public_key.public_numbers()
        n = public_numbers.n
        e = public_numbers.e
        
        print(f"[+] Public key loaded successfully")
        print(f"    - Modulus (n): {n}")
        print(f"    - Public exponent (e): {e}")
        print(f"    - Key size: {public_key.key_size} bits")
        
        return n, e
    
    except FileNotFoundError:
        print(f"[-] Error: Public key file not found: {key_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error loading public key: {e}")
        sys.exit(1)


def load_ciphertext(ciphertext_path):
    """
    Load the encrypted flag from file.
    
    Args:
        ciphertext_path: Path to the encrypted flag file
    
    Returns:
        int: Ciphertext as integer
    """
    print("\n[*] Loading encrypted flag...")
    try:
        with open(ciphertext_path, 'r') as f:
            content = f.read()
        
        # Extract the hex ciphertext from the file
        lines = content.split('\n')
        hex_ciphertext = None
        
        for i, line in enumerate(lines):
            if 'Encrypted Data (hexadecimal):' in line:
                # The hex data is 2 lines down
                hex_ciphertext = lines[i + 2].strip()
                break
        
        if not hex_ciphertext:
            print("[-] Error: Could not find ciphertext in file")
            sys.exit(1)
        
        c = int(hex_ciphertext, 16)
        print(f"[+] Ciphertext loaded successfully")
        print(f"    - Ciphertext (c): {c}")
        print(f"    - Hex length: {len(hex_ciphertext)} characters")
        
        return c
    
    except FileNotFoundError:
        print(f"[-] Error: Ciphertext file not found: {ciphertext_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error loading ciphertext: {e}")
        sys.exit(1)


def check_vulnerability(c, n, e):
    """
    Check if the ciphertext is vulnerable to cube root attack.
    
    Args:
        c: Ciphertext
        n: RSA modulus
        e: Public exponent
    
    Returns:
        bool: True if vulnerable
    """
    print("\n[*] Analyzing vulnerability...")
    
    if e != 3:
        print(f"[!] Warning: Public exponent is {e}, not 3")
        print(f"    This solver is designed for e=3 attacks")
        return False
    
    print(f"[+] Public exponent is 3 - checking for vulnerability...")
    
    # Compare bit lengths instead of actual values to avoid overflow
    c_bits = c.bit_length()
    n_bits = n.bit_length()
    
    # For cube root: if c < n, then likely m^3 < n (vulnerable)
    # We check bit lengths as a proxy
    print(f"    - Ciphertext bit length: {c_bits} bits")
    print(f"    - Modulus bit length: {n_bits} bits")
    
    if c_bits < n_bits:
        print(f"[+] VULNERABLE! The message is small enough for cube root attack")
        print(f"    m³ < n, so c = m³ mod n = m³")
        return True
    else:
        print(f"[-] Not vulnerable to simple cube root attack")
        return False


def perform_cube_root_attack(c, e):
    """
    Perform the cube root attack to recover the plaintext.
    
    Args:
        c: Ciphertext
        e: Public exponent (should be 3)
    
    Returns:
        int: Recovered plaintext as integer
    """
    print("\n[*] Performing cube root attack...")
    print(f"    - Computing {e}-th root of ciphertext...")
    
    # Use gmpy2 for fast and accurate integer root calculation
    # iroot returns (root, is_exact) tuple
    m, is_exact = gmpy2.iroot(c, e)
    
    if is_exact:
        print(f"[+] Exact root found!")
    else:
        print(f"[!] Approximate root found (not exact)")
        print(f"    This might indicate the message was larger or padding was used")
    
    print(f"    - Recovered plaintext (as integer): {m}")
    
    # Verify the result
    print(f"\n[*] Verifying result...")
    m_to_e = pow(int(m), e)
    
    print(f"    - m^{e} = {m_to_e}")
    print(f"    - c    = {c}")
    
    if m_to_e == c:
        print(f"[+] Verification successful! m^{e} = c")
    else:
        print(f"[-] Verification failed! m^{e} ≠ c")
        print(f"    Difference: {abs(m_to_e - c)}")
    
    return int(m)


def decode_plaintext(m):
    """
    Convert the recovered integer plaintext to the flag string.
    
    Args:
        m: Plaintext as integer
    
    Returns:
        str: Decoded flag
    """
    print("\n[*] Decoding plaintext to flag...")
    
    try:
        # Convert integer to bytes
        # Calculate number of bytes needed
        num_bytes = (m.bit_length() + 7) // 8
        plaintext_bytes = m.to_bytes(num_bytes, 'big')
        
        # Decode to string
        flag = plaintext_bytes.decode('utf-8')
        
        print(f"[+] Successfully decoded plaintext")
        print(f"    - Plaintext bytes: {plaintext_bytes}")
        print(f"    - Decoded string: {flag}")
        
        return flag
    
    except Exception as e:
        print(f"[-] Error decoding plaintext: {e}")
        print(f"    Raw integer value: {m}")
        return None


def display_solution_explanation():
    """Display an explanation of the attack."""
    print("\n" + "=" * 70)
    print(" ATTACK EXPLANATION")
    print("=" * 70)
    print("""
RSA Small Exponent Attack (e=3):

When RSA uses a small public exponent (e=3) and the plaintext message m
is small enough that m³ < n, the encryption becomes:

    c = m³ mod n = m³  (no modular reduction)

This means we can recover the plaintext by simply computing:

    m = ∛c  (cube root of c)

No need to factor n or break RSA!

This attack works because:
1. The message is short (typical for flags)
2. Even cubed, m³ is still smaller than the large modulus n
3. Without modular reduction, the ciphertext is just m cubed

Prevention:
- Use e=65537 (standard recommendation)
- Always use proper padding schemes (OAEP, PKCS#1 v2.0)
- Padding ensures the message is always large enough
""")
    print("=" * 70)


def main():
    """Main solver function."""
    print("=" * 70)
    print(" SMALLE CTF Challenge - Automated Solver")
    print(" RSA Small Exponent Attack (Cube Root)")
    print("=" * 70)
    
    # Determine paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    challenge_dir = os.path.dirname(script_dir)
    artifacts_dir = os.path.join(challenge_dir, 'artifacts')
    
    public_key_path = os.path.join(artifacts_dir, 'public_key.pem')
    ciphertext_path = os.path.join(artifacts_dir, 'encrypted_flag.txt')
    
    # Step 1: Load the public key
    n, e = load_public_key(public_key_path)
    
    # Step 2: Load the ciphertext
    c = load_ciphertext(ciphertext_path)
    
    # Step 3: Check vulnerability
    is_vulnerable = check_vulnerability(c, n, e)
    
    if not is_vulnerable:
        print("\n[-] This ciphertext may not be vulnerable to simple cube root attack")
        print("    Attempting attack anyway...")
    
    # Step 4: Perform the attack
    m = perform_cube_root_attack(c, e)
    
    # Step 5: Decode the plaintext
    flag = decode_plaintext(m)
    
    # Display results
    print("\n" + "=" * 70)
    print(" ATTACK SUCCESSFUL!")
    print("=" * 70)
    if flag:
        print(f"\n🚩 FLAG: {flag}\n")
    else:
        print("\n[-] Failed to decode flag")
    
    # Show explanation
    display_solution_explanation()
    
    print("\nChallenge solved! The flag has been recovered using a cube root attack.")
    print("This demonstrates why small exponents without padding are dangerous.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Solver interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
