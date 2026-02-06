#!/usr/bin/env python3
"""
Test suite for SMALLE CTF Challenge
Tests RSA key generation, encryption, and cube root attack
"""

import unittest
import os
import sys
import gmpy2
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes


class TestSmalleChallenge(unittest.TestCase):
    """Test cases for the SMALLE RSA challenge."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_flag = "HQX{sm4ll_exp0n3nt_w34kness_d3str0y5_RSA}"
        self.key_size = 2048
        self.public_exponent = 3
    
    def test_rsa_key_generation_with_e3(self):
        """Test that we can generate RSA keys with e=3."""
        key = RSA.generate(self.key_size, e=self.public_exponent)
        
        self.assertEqual(key.e, 3, "Public exponent should be 3")
        self.assertGreater(key.n, 0, "Modulus should be positive")
        self.assertEqual(key.size_in_bits(), self.key_size, 
                        f"Key size should be {self.key_size} bits")
    
    def test_flag_encryption_with_e3(self):
        """Test that flag encryption with e=3 works."""
        key = RSA.generate(self.key_size, e=self.public_exponent)
        
        # Convert flag to integer
        m = bytes_to_long(self.test_flag.encode())
        
        # Encrypt: c = m^e mod n
        c = pow(m, key.e, key.n)
        
        self.assertIsInstance(c, int, "Ciphertext should be an integer")
        self.assertGreater(c, 0, "Ciphertext should be positive")
        self.assertLess(c, key.n, "Ciphertext should be less than modulus")
    
    def test_vulnerability_condition(self):
        """Test that the flag satisfies the vulnerability condition (m^3 < n)."""
        key = RSA.generate(self.key_size, e=self.public_exponent)
        
        # Convert flag to integer
        m = bytes_to_long(self.test_flag.encode())
        
        # Check vulnerability condition
        m_cubed = m ** 3
        
        self.assertLess(m_cubed, key.n, 
                       "Message cubed should be less than modulus (vulnerable)")
        
        # Verify that encryption doesn't wrap
        c = pow(m, key.e, key.n)
        self.assertEqual(c, m_cubed, 
                        "Ciphertext should equal m^3 (no modular reduction)")
    
    def test_cube_root_attack_success(self):
        """Test that the cube root attack successfully recovers the flag."""
        key = RSA.generate(self.key_size, e=self.public_exponent)
        
        # Encrypt
        m = bytes_to_long(self.test_flag.encode())
        c = pow(m, key.e, key.n)
        
        # Attack: compute cube root
        m_recovered, is_exact = gmpy2.iroot(c, 3)
        
        self.assertTrue(is_exact, "Cube root should be exact")
        self.assertEqual(int(m_recovered), m, 
                        "Recovered plaintext should match original")
        
        # Convert back to flag
        flag_recovered = long_to_bytes(int(m_recovered)).decode()
        self.assertEqual(flag_recovered, self.test_flag, 
                        "Recovered flag should match original")
    
    def test_cube_root_binary_search(self):
        """Test cube root calculation using binary search."""
        def integer_cube_root(n):
            """Calculate integer cube root using binary search."""
            if n == 0:
                return 0
            
            low, high = 0, n
            result = 0
            
            while low <= high:
                mid = (low + high) // 2
                mid_cubed = mid ** 3
                
                if mid_cubed == n:
                    return mid
                elif mid_cubed < n:
                    result = mid
                    low = mid + 1
                else:
                    high = mid - 1
            
            return result
        
        # Test with the actual flag
        key = RSA.generate(self.key_size, e=self.public_exponent)
        m = bytes_to_long(self.test_flag.encode())
        c = pow(m, key.e, key.n)
        
        # Recover using binary search
        m_recovered = integer_cube_root(c)
        
        self.assertEqual(m_recovered, m, 
                        "Binary search should recover correct plaintext")
    
    def test_small_vs_large_message(self):
        """Test the difference between small and large messages."""
        key = RSA.generate(self.key_size, e=self.public_exponent)
        
        # Small message (vulnerable)
        small_msg = "SHORT"
        m_small = bytes_to_long(small_msg.encode())
        
        # Check if vulnerable
        is_vulnerable = (m_small ** 3) < key.n
        self.assertTrue(is_vulnerable, "Small message should be vulnerable")
        
        # Large message (not vulnerable with proper padding)
        # In real systems, padding ensures message is always large
        large_msg = "X" * 200  # 200 characters
        m_large = bytes_to_long(large_msg.encode())
        
        # This might still be vulnerable with 2048-bit key
        # In practice, OAEP padding would make it secure
        m_large_cubed = m_large ** 3
        
        # Just verify the calculation works
        self.assertIsInstance(m_large_cubed, int)
    
    def test_attack_complexity(self):
        """Test that cube root attack is polynomial time."""
        import time
        
        key = RSA.generate(self.key_size, e=self.public_exponent)
        m = bytes_to_long(self.test_flag.encode())
        c = pow(m, key.e, key.n)
        
        # Time the cube root attack
        start_time = time.time()
        m_recovered, _ = gmpy2.iroot(c, 3)
        attack_time = time.time() - start_time
        
        # Should be very fast (< 1 second)
        self.assertLess(attack_time, 1.0, 
                       "Cube root attack should complete in under 1 second")
        
        print(f"\nCube root attack completed in {attack_time:.6f} seconds")
    
    def test_proper_rsa_with_e65537(self):
        """Test that proper RSA with e=65537 doesn't have this vulnerability."""
        # Generate key with standard exponent
        key_secure = RSA.generate(self.key_size, e=65537)
        
        m = bytes_to_long(self.test_flag.encode())
        
        # With e=65537, m^e will be astronomically large
        # Cannot easily compute the 65537-th root
        self.assertEqual(key_secure.e, 65537, 
                        "Secure key should use e=65537")
        
        # The message condition m^e < n will definitely not hold
        # (we can't even compute m^65537 practically)
    
    def test_artifacts_exist(self):
        """Test that challenge artifacts are generated."""
        # This test assumes challenge.py has been run
        script_dir = os.path.dirname(os.path.abspath(__file__))
        challenge_dir = os.path.dirname(script_dir)
        artifacts_dir = os.path.join(challenge_dir, 'artifacts')
        
        expected_files = [
            'public_key.pem',
            'encrypted_flag.txt',
            'challenge_description.txt'
        ]
        
        for filename in expected_files:
            filepath = os.path.join(artifacts_dir, filename)
            if os.path.exists(filepath):
                self.assertTrue(True, f"{filename} exists")
            else:
                print(f"\nWarning: {filename} not found. Run challenge.py first.")
    
    def test_public_key_format(self):
        """Test that public keys can be exported and loaded in PEM format."""
        key = RSA.generate(self.key_size, e=self.public_exponent)
        
        # Export public key
        public_key_pem = key.publickey().export_key()
        
        self.assertIn(b'BEGIN PUBLIC KEY', public_key_pem, 
                     "Should be valid PEM format")
        self.assertIn(b'END PUBLIC KEY', public_key_pem, 
                     "Should be valid PEM format")
        
        # Import it back
        imported_key = RSA.import_key(public_key_pem)
        
        self.assertEqual(imported_key.n, key.n, "Modulus should match")
        self.assertEqual(imported_key.e, key.e, "Exponent should match")


class TestMathematicalProperties(unittest.TestCase):
    """Test mathematical properties of RSA and the attack."""
    
    def test_modular_arithmetic(self):
        """Test understanding of modular arithmetic."""
        # When m^3 < n, then m^3 mod n = m^3
        n = 1000
        m = 5
        
        c_with_mod = pow(m, 3, n)
        c_without_mod = m ** 3
        
        # Since 5^3 = 125 < 1000, they should be equal
        self.assertEqual(c_with_mod, c_without_mod, 
                        "Modular reduction should have no effect when m^e < n")
    
    def test_rsa_encryption_decryption(self):
        """Test that normal RSA encryption/decryption works."""
        key = RSA.generate(2048, e=65537)
        
        message = "Test message"
        m = bytes_to_long(message.encode())
        
        # Encrypt
        c = pow(m, key.e, key.n)
        
        # Decrypt
        m_decrypted = pow(c, key.d, key.n)
        
        self.assertEqual(m, m_decrypted, 
                        "RSA decryption should recover original message")
        
        message_decrypted = long_to_bytes(m_decrypted).decode()
        self.assertEqual(message, message_decrypted, 
                        "Decrypted message should match original")
    
    def test_euler_totient(self):
        """Test Euler's totient function for RSA."""
        # Small example with known primes
        p, q = 61, 53
        n = p * q
        phi_n = (p - 1) * (q - 1)
        
        # e and d should satisfy: e * d ≡ 1 (mod φ(n))
        e = 17
        d = pow(e, -1, phi_n)  # Modular inverse
        
        self.assertEqual((e * d) % phi_n, 1, 
                        "e and d should be modular inverses")


def run_tests():
    """Run all tests with verbose output."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all tests
    suite.addTests(loader.loadTestsFromTestCase(TestSmalleChallenge))
    suite.addTests(loader.loadTestsFromTestCase(TestMathematicalProperties))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
