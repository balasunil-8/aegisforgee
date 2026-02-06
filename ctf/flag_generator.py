"""
AegisForge CTF - Dynamic Flag Generation System

This module handles dynamic flag generation for CTF challenges.
Each user gets a unique flag to prevent answer sharing while maintaining
the same learning experience.

Key Features:
- Unique flags per user/challenge combination
- Deterministic generation (same user always gets same flag)
- Flag format validation
- Support for multiple flag patterns
"""

import hashlib
import secrets
from typing import Dict, Optional


class FlagGenerator:
    """
    Generates unique, user-specific flags for CTF challenges.
    
    Flags are generated deterministically based on user_id and challenge_id
    so that the same user always gets the same flag for a challenge.
    """
    
    def __init__(self, prefix: str = "HQX", secret_key: Optional[str] = None):
        """
        Initialize the flag generator.
        
        Args:
            prefix: Flag prefix (default: "HQX")
            secret_key: Secret key for hashing (generates random if not provided)
        """
        self.prefix = prefix
        self.secret_key = secret_key or secrets.token_hex(32)
    
    def generate_user_flag(self, challenge_id: str, user_id: str, 
                          flag_content: str) -> str:
        """
        Generate a unique flag for a specific user and challenge.
        
        The flag is deterministic - the same user_id and challenge_id
        will always produce the same flag.
        
        Args:
            challenge_id: Unique identifier for the challenge
            user_id: Unique identifier for the user
            flag_content: Base content of the flag
            
        Returns:
            Complete flag string in format: HQX{content_hash}
            
        Example:
            >>> gen = FlagGenerator()
            >>> flag = gen.generate_user_flag("area64", "user123", "base64_decoded")
            >>> print(flag)
            HQX{base64_decoded_a1b2c3d4}
        """
        # Create a unique seed combining challenge, user, and secret
        seed = f"{challenge_id}:{user_id}:{self.secret_key}"
        
        # Generate deterministic hash
        hash_obj = hashlib.sha256(seed.encode())
        hash_suffix = hash_obj.hexdigest()[:8]
        
        # Construct the final flag
        flag = f"{self.prefix}{{{flag_content}_{hash_suffix}}}"
        
        return flag
    
    def generate_static_flag(self, challenge_id: str, flag_content: str) -> str:
        """
        Generate a static flag (same for all users).
        
        Use this for challenges where flag sharing is not a concern
        or where the challenge design requires a static flag.
        
        Args:
            challenge_id: Unique identifier for the challenge
            flag_content: Content of the flag
            
        Returns:
            Complete flag string
        """
        return f"{self.prefix}{{{flag_content}}}"
    
    def verify_flag(self, submitted: str, expected: str) -> bool:
        """
        Verify if a submitted flag matches the expected flag.
        
        Comparison is case-sensitive and strips whitespace.
        
        Args:
            submitted: Flag submitted by the user
            expected: Expected correct flag
            
        Returns:
            True if flags match, False otherwise
        """
        return submitted.strip() == expected.strip()
    
    def verify_flag_pattern(self, submitted: str) -> bool:
        """
        Verify if a submitted string matches the expected flag pattern.
        
        Checks:
        - Starts with correct prefix
        - Contains curly braces
        - Has content between braces
        
        Args:
            submitted: String to validate
            
        Returns:
            True if string matches flag pattern, False otherwise
        """
        submitted = submitted.strip()
        
        # Check basic structure: PREFIX{content}
        if not submitted.startswith(f"{self.prefix}{{"):
            return False
        
        if not submitted.endswith("}"):
            return False
        
        # Extract content between braces
        try:
            content = submitted[len(self.prefix)+1:-1]
            # Flag should have some content
            return len(content) > 0
        except:
            return False
    
    def get_flag_hint(self, flag: str, reveal_chars: int = 3) -> str:
        """
        Generate a hint by partially revealing the flag.
        
        Shows the first few characters of the flag content.
        
        Args:
            flag: The complete flag
            reveal_chars: Number of characters to reveal
            
        Returns:
            Partially revealed flag
            
        Example:
            >>> hint = gen.get_flag_hint("HQX{secret_content}", 3)
            >>> print(hint)
            HQX{sec...}
        """
        try:
            # Extract content between braces
            start = flag.index("{") + 1
            end = flag.index("}")
            content = flag[start:end]
            
            # Show first N characters
            if len(content) <= reveal_chars:
                revealed = content
            else:
                revealed = content[:reveal_chars] + "..."
            
            return f"{self.prefix}{{{revealed}}}"
        except:
            return f"{self.prefix}{{???}}"


class ChallengeFlagTemplates:
    """
    Predefined flag content templates for different challenges.
    
    This centralizes flag content to ensure consistency and
    makes it easy to update flag contents.
    """
    
    TEMPLATES = {
        'area64': 'b4s364_1s_n0t_encrypti0n',
        'smalle': 'sm4ll_exp0n3nt_w34kness',
        'hidden_layers': 'h1dd3n_1n_pl41n_s1ght',
        'paper_script': 'm3t4d4t4_r3v34ls_s3cr3ts',
        'synthetic_stacks': 'l4y3rs_up0n_l4y3rs_d3c0d3d',
    }
    
    @classmethod
    def get_flag_content(cls, challenge_id: str) -> str:
        """
        Get the flag content template for a challenge.
        
        Args:
            challenge_id: ID of the challenge
            
        Returns:
            Flag content string
        """
        return cls.TEMPLATES.get(challenge_id, f"challenge_{challenge_id}_solved")
    
    @classmethod
    def get_all_templates(cls) -> Dict[str, str]:
        """Get all flag templates as a dictionary."""
        return cls.TEMPLATES.copy()


if __name__ == '__main__':
    # Example usage
    print("=== Flag Generator Demo ===\n")
    
    generator = FlagGenerator()
    
    # Generate flags for different users
    print("1. User-specific flags:")
    for user in ['alice', 'bob', 'charlie']:
        flag = generator.generate_user_flag('area64', user, 
                                           ChallengeFlagTemplates.get_flag_content('area64'))
        print(f"   {user}: {flag}")
    
    print("\n2. Static flag:")
    static_flag = generator.generate_static_flag('demo', 'this_is_static')
    print(f"   {static_flag}")
    
    print("\n3. Flag verification:")
    test_flag = "HQX{test_flag_12345678}"
    print(f"   Flag: {test_flag}")
    print(f"   Valid pattern: {generator.verify_flag_pattern(test_flag)}")
    print(f"   Matches itself: {generator.verify_flag(test_flag, test_flag)}")
    print(f"   Matches different: {generator.verify_flag(test_flag, 'HQX{wrong}')}")
    
    print("\n4. Flag hint:")
    hint = generator.get_flag_hint(test_flag, 4)
    print(f"   Original: {test_flag}")
    print(f"   Hint: {hint}")
