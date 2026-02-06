#!/usr/bin/env python3
"""
Test Suite for AREA64 Challenge

This module contains comprehensive tests for the AREA64 CTF challenge,
including flag generation, encoding/decoding, and verification tests.

Run with: pytest test_area64.py -v
"""

import pytest
import sys
import os
import base64
import json

# Add parent directory to path to import challenge module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from challenge import Area64Challenge


class TestArea64Challenge:
    """Test cases for the AREA64 challenge."""
    
    @pytest.fixture
    def challenge(self):
        """Create a challenge instance for testing."""
        return Area64Challenge()
    
    def test_challenge_initialization(self, challenge):
        """Test that challenge initializes with correct metadata."""
        assert challenge.challenge_id == "area64"
        assert challenge.name == "AREA64"
        assert challenge.category == "Cryptography"
        assert challenge.difficulty == "Beginner"
        assert challenge.points == 100
        assert challenge.flag.startswith("HQX{")
        assert challenge.flag.endswith("}")
    
    def test_flag_format(self, challenge):
        """Test that the flag follows the correct format."""
        flag = challenge.flag
        assert flag.startswith("HQX{"), "Flag should start with HQX{"
        assert flag.endswith("}"), "Flag should end with }"
        assert len(flag) > 10, "Flag should have meaningful content"
        assert "b4s364" in flag, "Flag should reference base64"
        assert "encrypti0n" in flag, "Flag should reference encryption"
    
    def test_generate_challenge(self, challenge):
        """Test challenge generation returns expected data."""
        result = challenge.generate_challenge()
        
        assert "encoded_flag" in result
        assert "message_content" in result
        assert "instructions" in result
        assert "flag" in result
        
        assert result["flag"] == challenge.flag
        assert isinstance(result["encoded_flag"], str)
        assert isinstance(result["message_content"], str)
        assert isinstance(result["instructions"], str)
    
    def test_base64_encoding(self, challenge):
        """Test that flag is correctly Base64 encoded."""
        result = challenge.generate_challenge()
        encoded_flag = result["encoded_flag"]
        
        # Decode the encoded flag
        decoded = base64.b64decode(encoded_flag).decode()
        
        # Should match the original flag
        assert decoded == challenge.flag
    
    def test_base64_decoding(self, challenge):
        """Test that we can decode the encoded flag back to original."""
        result = challenge.generate_challenge()
        encoded_flag = result["encoded_flag"]
        
        # Test decoding
        decoded_bytes = base64.b64decode(encoded_flag)
        decoded_string = decoded_bytes.decode('utf-8')
        
        assert decoded_string == challenge.flag
        assert decoded_string.startswith("HQX{")
    
    def test_verify_flag_correct(self, challenge):
        """Test flag verification with correct flag."""
        assert challenge.verify_flag(challenge.flag) == True
        assert challenge.verify_flag(challenge.flag.strip()) == True
    
    def test_verify_flag_incorrect(self, challenge):
        """Test flag verification with incorrect flags."""
        assert challenge.verify_flag("HQX{wrong_flag}") == False
        assert challenge.verify_flag("wrong_format") == False
        assert challenge.verify_flag("") == False
        assert challenge.verify_flag("HQX{") == False
    
    def test_verify_flag_case_sensitive(self, challenge):
        """Test that flag verification is case-sensitive."""
        wrong_case = challenge.flag.upper()
        if wrong_case != challenge.flag:
            assert challenge.verify_flag(wrong_case) == False
    
    def test_message_content(self, challenge):
        """Test that message content contains expected elements."""
        result = challenge.generate_challenge()
        message = result["message_content"]
        
        # Check for key elements
        assert "AREA 64" in message or "Area 64" in message
        assert "CLASSIFIED" in message or "INTERCEPT" in message
        assert result["encoded_flag"] in message
        assert "encode" in message.lower() or "encoding" in message.lower()
    
    def test_instructions_content(self, challenge):
        """Test that instructions contain helpful information."""
        result = challenge.generate_challenge()
        instructions = result["instructions"]
        
        assert "OBJECTIVE" in instructions or "objective" in instructions
        assert "decode" in instructions.lower()
        assert "base64" in instructions.lower() or "encoding" in instructions.lower()
        assert "HQX{" in instructions
    
    def test_encoded_flag_is_valid_base64(self, challenge):
        """Test that encoded flag is valid Base64."""
        result = challenge.generate_challenge()
        encoded_flag = result["encoded_flag"]
        
        # Should not raise an exception
        try:
            base64.b64decode(encoded_flag)
            valid = True
        except Exception:
            valid = False
        
        assert valid, "Encoded flag should be valid Base64"
    
    def test_encoded_flag_characteristics(self, challenge):
        """Test that encoded flag has Base64 characteristics."""
        result = challenge.generate_challenge()
        encoded_flag = result["encoded_flag"]
        
        # Base64 uses only these characters
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        flag_chars = set(encoded_flag)
        
        assert flag_chars.issubset(valid_chars), "Encoded flag should only use Base64 characters"
    
    def test_challenge_metadata(self, challenge):
        """Test challenge metadata values."""
        assert isinstance(challenge.points, int)
        assert challenge.points > 0
        assert challenge.difficulty in ["Beginner", "Easy", "Medium", "Hard", "Expert"]
        assert len(challenge.category) > 0


class TestChallengeFiles:
    """Test challenge file operations."""
    
    @pytest.fixture
    def challenge(self):
        """Create a challenge instance for testing."""
        return Area64Challenge()
    
    def test_challenge_json_exists(self):
        """Test that challenge.json exists and is valid."""
        json_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "challenge.json"
        )
        
        assert os.path.exists(json_path), "challenge.json should exist"
        
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        assert "id" in data
        assert "name" in data
        assert "category" in data
        assert "difficulty" in data
        assert "points" in data
    
    def test_artifacts_directory_exists(self):
        """Test that artifacts directory exists."""
        artifacts_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "artifacts"
        )
        assert os.path.exists(artifacts_path), "artifacts directory should exist"
    
    def test_encoded_message_exists(self):
        """Test that encoded_message.txt exists."""
        message_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "artifacts",
            "encoded_message.txt"
        )
        assert os.path.exists(message_path), "encoded_message.txt should exist"
    
    def test_instructions_exist(self):
        """Test that instructions.txt exists."""
        instructions_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "artifacts",
            "instructions.txt"
        )
        assert os.path.exists(instructions_path), "instructions.txt should exist"


class TestBase64Fundamentals:
    """Test Base64 encoding/decoding fundamentals."""
    
    def test_basic_base64_encode(self):
        """Test basic Base64 encoding."""
        text = "Hello, World!"
        encoded = base64.b64encode(text.encode()).decode()
        assert encoded == "SGVsbG8sIFdvcmxkIQ=="
    
    def test_basic_base64_decode(self):
        """Test basic Base64 decoding."""
        encoded = "SGVsbG8sIFdvcmxkIQ=="
        decoded = base64.b64decode(encoded).decode()
        assert decoded == "Hello, World!"
    
    def test_flag_encode_decode_cycle(self):
        """Test that encoding and decoding a flag works correctly."""
        original = "HQX{test_flag_12345}"
        encoded = base64.b64encode(original.encode()).decode()
        decoded = base64.b64decode(encoded).decode()
        assert decoded == original


class TestSolverScript:
    """Test the solver script functionality."""
    
    def test_solver_can_read_message(self):
        """Test that solver can read the encoded message."""
        message_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "artifacts",
            "encoded_message.txt"
        )
        
        if os.path.exists(message_path):
            with open(message_path, 'r') as f:
                content = f.read()
            assert len(content) > 0
            
            # Should contain Base64 encoded string
            lines = content.split('\n')
            found_encoded = False
            for line in lines:
                if len(line.strip()) > 20 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in line.strip()):
                    found_encoded = True
                    break
            
            assert found_encoded, "Message should contain Base64 encoded string"


def test_challenge_completeness():
    """Test that all required challenge components exist."""
    base_path = os.path.dirname(os.path.dirname(__file__))
    
    required_files = [
        "README.md",
        "challenge.json",
        "challenge.py",
        "artifacts/encoded_message.txt",
        "artifacts/instructions.txt",
        "solution/SOLUTION.md",
        "solution/solve.py",
        "solution/hints.json",
        "tests/test_area64.py"
    ]
    
    for file_path in required_files:
        full_path = os.path.join(base_path, file_path)
        assert os.path.exists(full_path), f"Required file missing: {file_path}"


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
