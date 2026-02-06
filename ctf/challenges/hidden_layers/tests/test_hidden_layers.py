#!/usr/bin/env python3
"""
Tests for HIDDEN_LAYERS CTF Challenge
Tests LSB steganography encoding and decoding functionality
"""

import os
import sys
import unittest
from PIL import Image

# Add parent directory to path to import challenge module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from challenge import LSBSteganography, create_base_image


class TestLSBSteganography(unittest.TestCase):
    """Test cases for LSB steganography implementation"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = os.path.dirname(os.path.abspath(__file__))
        self.temp_image = os.path.join(self.test_dir, 'temp_test_image.png')
        self.stego_image = os.path.join(self.test_dir, 'temp_stego_image.png')
        
    def tearDown(self):
        """Clean up test files"""
        for file in [self.temp_image, self.stego_image]:
            if os.path.exists(file):
                os.remove(file)
    
    def test_text_to_binary_conversion(self):
        """Test text to binary conversion"""
        text = "HQX"
        expected = "010010000101000101011000"  # Binary for 'H', 'Q', 'X'
        result = LSBSteganography.text_to_binary(text)
        self.assertEqual(result, expected)
    
    def test_binary_to_text_conversion(self):
        """Test binary to text conversion"""
        binary = "010010000101000101011000"  # Binary for 'H', 'Q', 'X'
        expected = "HQX"
        result = LSBSteganography.binary_to_text(binary)
        self.assertEqual(result, expected)
    
    def test_round_trip_conversion(self):
        """Test text -> binary -> text conversion"""
        original = "HQX{test_flag_123}"
        binary = LSBSteganography.text_to_binary(original)
        decoded = LSBSteganography.binary_to_text(binary)
        self.assertEqual(original, decoded)
    
    def test_hide_and_extract_simple_message(self):
        """Test hiding and extracting a simple message"""
        # Create test image
        create_base_image(200, 200, self.temp_image)
        
        # Hide message
        message = "TEST"
        LSBSteganography.hide_data_in_image(
            self.temp_image, message, self.stego_image
        )
        
        # Verify stego image exists
        self.assertTrue(os.path.exists(self.stego_image))
        
        # Extract message
        extracted = LSBSteganography.extract_data_from_image(self.stego_image)
        self.assertEqual(message, extracted.strip())
    
    def test_hide_and_extract_flag(self):
        """Test hiding and extracting the actual challenge flag"""
        # Create test image
        create_base_image(400, 300, self.temp_image)
        
        # Hide flag
        flag = "HQX{h1dd3n_1n_pl41n_s1ght_st3g0}"
        LSBSteganography.hide_data_in_image(
            self.temp_image, flag, self.stego_image
        )
        
        # Extract flag
        extracted = LSBSteganography.extract_data_from_image(self.stego_image)
        self.assertEqual(flag, extracted.strip())
    
    def test_hide_long_message(self):
        """Test hiding a longer message"""
        # Create larger image
        create_base_image(500, 400, self.temp_image)
        
        # Hide long message
        message = "This is a longer test message to verify that LSB steganography works correctly with multiple sentences and special characters! @#$%^&*()"
        LSBSteganography.hide_data_in_image(
            self.temp_image, message, self.stego_image
        )
        
        # Extract message
        extracted = LSBSteganography.extract_data_from_image(self.stego_image)
        self.assertEqual(message, extracted.strip())
    
    def test_image_size_validation(self):
        """Test that image size validation works"""
        # Create tiny image
        tiny_img = Image.new('RGB', (10, 10))
        tiny_img.save(self.temp_image, 'PNG')
        
        # Try to hide large message (should raise error)
        large_message = "A" * 1000
        with self.assertRaises(ValueError):
            LSBSteganography.hide_data_in_image(
                self.temp_image, large_message, self.stego_image
            )
    
    def test_image_remains_valid_after_encoding(self):
        """Test that the stego image is still a valid PNG"""
        create_base_image(300, 300, self.temp_image)
        
        message = "HQX{test}"
        LSBSteganography.hide_data_in_image(
            self.temp_image, message, self.stego_image
        )
        
        # Try to open stego image (should not raise exception)
        img = Image.open(self.stego_image)
        self.assertEqual(img.format, 'PNG')
        self.assertEqual(img.size, (300, 300))
    
    def test_visual_similarity(self):
        """Test that stego image looks similar to original"""
        create_base_image(200, 200, self.temp_image)
        
        message = "HQX{test}"
        LSBSteganography.hide_data_in_image(
            self.temp_image, message, self.stego_image
        )
        
        # Load both images
        original = Image.open(self.temp_image).convert('RGB')
        stego = Image.open(self.stego_image).convert('RGB')
        
        # Get pixel data
        orig_pixels = list(original.getdata())
        stego_pixels = list(stego.getdata())
        
        # Check that most pixels differ by at most 1
        differences = 0
        for orig, steg in zip(orig_pixels, stego_pixels):
            for o, s in zip(orig, steg):
                if abs(o - s) > 1:
                    differences += 1
        
        # Should have very few large differences
        self.assertLess(differences, len(orig_pixels) * 0.01)
    
    def test_special_characters(self):
        """Test hiding message with special characters"""
        create_base_image(300, 200, self.temp_image)
        
        message = "HQX{sp3c!al_ch@rs_#123$%^&*()}"
        LSBSteganography.hide_data_in_image(
            self.temp_image, message, self.stego_image
        )
        
        extracted = LSBSteganography.extract_data_from_image(self.stego_image)
        self.assertEqual(message, extracted.strip())
    
    def test_eof_marker_detection(self):
        """Test that EOF marker is properly added and detected"""
        create_base_image(200, 200, self.temp_image)
        
        message = "SHORT"
        LSBSteganography.hide_data_in_image(
            self.temp_image, message, self.stego_image
        )
        
        # Extract should stop at EOF marker
        extracted = LSBSteganography.extract_data_from_image(self.stego_image)
        
        # Should only contain the message, not garbage after it
        self.assertEqual(message, extracted.strip())
        self.assertLess(len(extracted), len(message) + 10)


class TestChallengeGeneration(unittest.TestCase):
    """Test challenge file generation"""
    
    def test_base_image_creation(self):
        """Test that base image is created correctly"""
        test_file = 'test_base.png'
        try:
            create_base_image(400, 300, test_file)
            
            # Verify image exists and has correct properties
            self.assertTrue(os.path.exists(test_file))
            img = Image.open(test_file)
            self.assertEqual(img.size, (400, 300))
            self.assertEqual(img.format, 'PNG')
            
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)
    
    def test_challenge_image_contains_flag(self):
        """Test that the generated challenge image contains the flag"""
        # Path to actual challenge image
        challenge_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        image_path = os.path.join(challenge_dir, 'artifacts', 'mystery_image.png')
        
        # Skip if challenge hasn't been generated yet
        if not os.path.exists(image_path):
            self.skipTest("Challenge not generated yet")
        
        # Extract flag
        extracted = LSBSteganography.extract_data_from_image(image_path)
        
        # Verify flag format
        self.assertIn('HQX{', extracted)
        self.assertIn('}', extracted)
        
        # Extract just the flag
        start = extracted.find('HQX{')
        end = extracted.find('}', start) + 1
        flag = extracted[start:end]
        
        # Verify flag format
        self.assertTrue(flag.startswith('HQX{'))
        self.assertTrue(flag.endswith('}'))
        self.assertGreater(len(flag), 10)


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestLSBSteganography))
    suite.addTests(loader.loadTestsFromTestCase(TestChallengeGeneration))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
