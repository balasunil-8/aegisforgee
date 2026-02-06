#!/usr/bin/env python3
"""
SMALLE CTF Challenge - Small Exponent RSA Attack
Generates an RSA key pair with e=3 and encrypts a flag.

This demonstrates the vulnerability of using small public exponents
when the plaintext message is small enough that m^e < n.
"""

import os
import sys
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes


def generate_vulnerable_rsa(key_size=2048):
    """
    Generate an RSA key pair with a small public exponent (e=3).
    
    Args:
        key_size: Size of the RSA key in bits (default: 2048)
    
    Returns:
        RSA key object with e=3
    """
    print(f"[+] Generating {key_size}-bit RSA key with e=3...")
    key = RSA.generate(key_size, e=3)
    print(f"[+] Key generated successfully")
    print(f"    - Modulus (n): {key.n}")
    print(f"    - Public exponent (e): {key.e}")
    print(f"    - Key size: {key.size_in_bits()} bits")
    return key


def encrypt_flag(public_key, flag):
    """
    Encrypt the flag using RSA with the vulnerable small exponent.
    
    Args:
        public_key: RSA public key object
        flag: Flag string to encrypt
    
    Returns:
        Encrypted flag as integer
    """
    # Convert flag to integer
    m = bytes_to_long(flag.encode())
    print(f"\n[+] Encrypting flag...")
    print(f"    - Plaintext (m): {m}")
    print(f"    - Message length: {len(flag)} characters")
    
    # Perform RSA encryption: c = m^e mod n
    n = public_key.n
    e = public_key.e
    c = pow(m, e, n)
    
    print(f"    - Ciphertext (c): {c}")
    
    # Check if vulnerable to cube root attack
    m_cubed = m ** e
    if m_cubed < n:
        print(f"\n[!] VULNERABILITY DETECTED!")
        print(f"    m^{e} = {m_cubed}")
        print(f"    n = {n}")
        print(f"    Since m^{e} < n, the ciphertext is vulnerable to cube root attack!")
    else:
        print(f"\n[+] m^{e} >= n, wrapping occurs (more secure)")
    
    return c


def export_public_key(key, filename):
    """
    Export the public key in PEM format.
    
    Args:
        key: RSA key object
        filename: Output filename for the public key
    """
    public_key = key.publickey().export_key()
    with open(filename, 'wb') as f:
        f.write(public_key)
    print(f"\n[+] Public key exported to: {filename}")


def export_encrypted_flag(ciphertext, filename):
    """
    Export the encrypted flag in hexadecimal format.
    
    Args:
        ciphertext: Encrypted flag as integer
        filename: Output filename for the ciphertext
    """
    with open(filename, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write(" INTERCEPTED ENCRYPTED MESSAGE\n")
        f.write("=" * 70 + "\n\n")
        f.write("During routine network monitoring, we intercepted this encrypted\n")
        f.write("message from what appears to be a secure authentication system.\n")
        f.write("The encryption uses RSA, but something seems off about the\n")
        f.write("implementation...\n\n")
        f.write("Encrypted Data (hexadecimal):\n")
        f.write("-" * 70 + "\n")
        f.write(hex(ciphertext)[2:] + "\n")
        f.write("-" * 70 + "\n\n")
        f.write("Your task: Decrypt this message and recover the flag.\n")
        f.write("The public key has been provided separately.\n\n")
    print(f"[+] Encrypted flag exported to: {filename}")


def create_challenge_description(filename):
    """
    Create a detailed challenge description file.
    
    Args:
        filename: Output filename for the description
    """
    description = """INTERCEPTED COMMUNICATION - CLASSIFIED
=====================================

DATE: 2024-01-15
TIME: 14:32:17 UTC
SOURCE: Corporate Authentication Portal (10.0.0.42)
DESTINATION: Authentication Server (10.0.0.100)
PROTOCOL: HTTPS (TLS 1.3)

INCIDENT REPORT:
---------------

During a penetration testing engagement, our team discovered that the
target organization's authentication system uses RSA encryption to protect
login credentials in transit. However, a critical misconfiguration was
identified in their cryptographic implementation.

TECHNICAL ANALYSIS:
------------------

The system developers opted to use RSA with a public exponent of e=3,
citing "performance optimization" as the rationale. This decision was
made to reduce computational overhead during the encryption process.

While it's true that smaller exponents can improve encryption speed,
this optimization comes at a severe security cost when not implemented
carefully.

VULNERABILITY ASSESSMENT:
------------------------

RSA with e=3 is vulnerable to cube root attacks when the plaintext
message satisfies certain conditions. Specifically, if the message m
is small enough that m^3 < n (where n is the RSA modulus), then the
encryption does not benefit from the modular reduction that provides
RSA's security.

In such cases:
  c = m^3 mod n = m^3 (no wrapping)

An attacker can simply compute the cube root of c to recover m, without
needing to factor the modulus or break RSA's mathematical hardness.

YOUR MISSION:
------------

Analyze the provided public key and encrypted message. Determine if the
implementation is vulnerable and, if so, exploit the weakness to recover
the plaintext flag.

FILES PROVIDED:
--------------
1. public_key.pem - RSA public key
2. encrypted_flag.txt - Intercepted encrypted message

SECURITY IMPLICATIONS:
---------------------

This vulnerability demonstrates why cryptographic best practices must
be followed rigorously. The standard recommendation is to use e=65537
(0x10001), which provides a good balance between security and performance.

Good luck!

---
AegisForge Red Team
"""
    
    with open(filename, 'w') as f:
        f.write(description)
    print(f"[+] Challenge description exported to: {filename}")


def main():
    """Main function to generate the SMALLE CTF challenge."""
    print("=" * 70)
    print(" SMALLE CTF Challenge Generator")
    print(" Small Exponent RSA Attack")
    print("=" * 70)
    
    # Set up paths
    artifacts_dir = os.path.join(os.path.dirname(__file__), 'artifacts')
    os.makedirs(artifacts_dir, exist_ok=True)
    
    # Define the flag
    flag = "HQX{sm4ll_exp0n3nt_w34kness_d3str0y5_RSA}"
    print(f"\n[+] Flag: {flag}")
    
    # Generate vulnerable RSA key
    key = generate_vulnerable_rsa(key_size=2048)
    
    # Encrypt the flag
    ciphertext = encrypt_flag(key, flag)
    
    # Export artifacts
    public_key_path = os.path.join(artifacts_dir, 'public_key.pem')
    encrypted_flag_path = os.path.join(artifacts_dir, 'encrypted_flag.txt')
    description_path = os.path.join(artifacts_dir, 'challenge_description.txt')
    
    export_public_key(key, public_key_path)
    export_encrypted_flag(ciphertext, encrypted_flag_path)
    create_challenge_description(description_path)
    
    print("\n" + "=" * 70)
    print(" Challenge Generation Complete!")
    print("=" * 70)
    print(f"\nArtifacts created in: {artifacts_dir}")
    print("\nTo solve this challenge:")
    print("1. Examine the public key to extract n and e")
    print("2. Note that e=3 (small exponent)")
    print("3. Calculate the cube root of the ciphertext")
    print("4. Convert the result back to the flag string")
    print("\nFor a complete solution, see: solution/SOLUTION.md")


if __name__ == '__main__':
    main()
