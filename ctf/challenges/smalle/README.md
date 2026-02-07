# SMALLE - Small Exponent RSA Attack

**Category:** Cryptography  
**Difficulty:** Intermediate  
**Points:** 200  
**Author:** AegisForge Security Team

## 🎯 Challenge Overview

You've intercepted an encrypted login credential from a supposedly "secure" authentication system. The developers used RSA encryption but made a critical mistake in their implementation - they chose convenience over security.

Your mission: Decrypt the intercepted message and recover the flag.

## 📖 Scenario

During a routine security audit, you captured encrypted traffic from a corporate login portal. The system uses RSA encryption to protect user credentials in transit. However, analysis of the public key reveals a critical vulnerability that could compromise the entire authentication system.

The encryption implementation uses RSA with a public exponent of **e = 3** for "performance reasons." The developers believed that a smaller exponent would make encryption faster without sacrificing security. They were wrong.

## 🔍 What You'll Learn

- **RSA Cryptography Fundamentals**: Understanding the RSA algorithm and its mathematical foundation
- **Small Exponent Attack**: Why choosing e=3 creates a devastating vulnerability
- **Cube Root Attack**: How to exploit small exponents when m³ < n
- **Security Trade-offs**: Why performance optimizations can introduce critical vulnerabilities
- **Best Practices**: Proper RSA parameter selection (why e=65537 is standard)

## 🚨 The Vulnerability

When RSA uses a small public exponent (like e=3) and the plaintext message is small enough that m³ < n (where n is the modulus), the encryption doesn't "wrap around" the modulus. This means:

```
c = m³ mod n = m³
```

In this case, you can simply compute the cube root of the ciphertext to recover the plaintext - no need to factor the modulus or break RSA!

## 📦 Files Provided

- `public_key.pem` - The RSA public key (containing n and e)
- `encrypted_flag.txt` - The encrypted flag in hexadecimal format
- `challenge_description.txt` - Additional context about the interception

## 🎓 Learning Objectives

After completing this challenge, you should understand:

1. How RSA encryption works mathematically
2. The role of the public exponent in RSA security
3. Why small exponents create vulnerabilities
4. How to perform cube root attacks on RSA
5. Industry best practices for RSA parameter selection

## 💡 Hints Available

This challenge includes progressive hints if you get stuck:
- **Hint 1** (20 points): Understanding the vulnerability
- **Hint 2** (40 points): Mathematical approach
- **Hint 3** (60 points): Implementation guidance

## 🏁 Flag Format

`HQX{sm4ll_exp0n3nt_w34kness_XXXXX}`

## 🛠️ Recommended Tools

- Python with `cryptography` library for key parsing
- `gmpy2` for arbitrary precision arithmetic
- Basic understanding of modular arithmetic
- Optional: `RsaCtfTool` for automated exploitation

## 🚀 Getting Started

1. Examine the public key to understand the RSA parameters
2. Analyze the encrypted flag
3. Consider what happens when e=3 and the message is small
4. Think about how you might reverse the encryption without breaking RSA

Good luck, and remember: in cryptography, seemingly small choices can have massive security implications!

---

*This challenge is part of the AegisForge CTF platform - Learn by Breaking, Secure by Building*
