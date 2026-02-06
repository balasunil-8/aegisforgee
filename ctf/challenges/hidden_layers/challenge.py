#!/usr/bin/env python3
"""
HIDDEN_LAYERS - LSB Steganography Challenge
AegisForge CTF Challenge Generator

This module generates a steganography challenge where a flag is hidden
in the Least Significant Bits (LSB) of an image's pixel data.
"""

import os
from PIL import Image, ImageDraw, ImageFont
import random


class LSBSteganography:
    """LSB (Least Significant Bit) Steganography Implementation"""
    
    @staticmethod
    def text_to_binary(text):
        """Convert text to binary string"""
        binary = ''.join(format(ord(char), '08b') for char in text)
        return binary
    
    @staticmethod
    def binary_to_text(binary):
        """Convert binary string to text"""
        # Split into 8-bit chunks
        chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
        # Convert each byte to character
        text = ''.join(chr(int(byte, 2)) for byte in chars if len(byte) == 8)
        return text
    
    @staticmethod
    def hide_data_in_image(image_path, secret_message, output_path):
        """
        Hide secret message in image using LSB steganography
        
        Args:
            image_path: Path to source image
            secret_message: Text to hide
            output_path: Path to save stego image
        """
        # Open image
        img = Image.open(image_path)
        img = img.convert('RGB')  # Ensure RGB mode
        
        # Convert message to binary
        binary_message = LSBSteganography.text_to_binary(secret_message)
        # Add delimiter to mark end of message
        binary_message += '1111111111111110'  # EOF marker
        
        # Check if image is large enough
        max_bytes = img.width * img.height * 3  # 3 channels (RGB)
        if len(binary_message) > max_bytes:
            raise ValueError("Image too small to hide the message!")
        
        # Get pixel data
        pixels = list(img.getdata())
        new_pixels = []
        
        data_index = 0
        for pixel in pixels:
            r, g, b = pixel
            
            # Modify LSB of each channel if we have data left
            if data_index < len(binary_message):
                r = (r & 0xFE) | int(binary_message[data_index])
                data_index += 1
            if data_index < len(binary_message):
                g = (g & 0xFE) | int(binary_message[data_index])
                data_index += 1
            if data_index < len(binary_message):
                b = (b & 0xFE) | int(binary_message[data_index])
                data_index += 1
            
            new_pixels.append((r, g, b))
        
        # Create new image with modified pixels
        stego_img = Image.new('RGB', img.size)
        stego_img.putdata(new_pixels)
        stego_img.save(output_path, 'PNG')
        
        print(f"[+] Message hidden in image: {output_path}")
        print(f"[+] Message length: {len(secret_message)} characters ({len(binary_message)} bits)")
    
    @staticmethod
    def extract_data_from_image(image_path):
        """
        Extract hidden message from image using LSB steganography
        
        Args:
            image_path: Path to stego image
            
        Returns:
            Extracted message as string
        """
        # Open image
        img = Image.open(image_path)
        img = img.convert('RGB')
        
        # Extract LSB from each pixel
        binary_data = ""
        pixels = list(img.getdata())
        
        for pixel in pixels:
            r, g, b = pixel
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)
        
        # Find EOF marker (1111111111111110)
        eof_marker = '1111111111111110'
        eof_pos = binary_data.find(eof_marker)
        
        if eof_pos != -1:
            binary_data = binary_data[:eof_pos]
        
        # Convert binary to text
        message = LSBSteganography.binary_to_text(binary_data)
        return message


def create_base_image(width=800, height=600, output_path='base_image.png'):
    """
    Create a base image with a gradient and geometric pattern
    """
    img = Image.new('RGB', (width, height))
    draw = ImageDraw.Draw(img)
    
    # Create gradient background
    for y in range(height):
        # Purple to blue gradient
        r = int(120 - (y / height) * 40)
        g = int(80 + (y / height) * 80)
        b = int(200 + (y / height) * 55)
        draw.line([(0, y), (width, y)], fill=(r, g, b))
    
    # Add geometric patterns
    # Circles
    for i in range(15):
        x = random.randint(50, width - 50)
        y = random.randint(50, height - 50)
        radius = random.randint(20, 60)
        color = (
            random.randint(150, 255),
            random.randint(150, 255),
            random.randint(150, 255)
        )
        draw.ellipse([x - radius, y - radius, x + radius, y + radius], 
                     outline=color, width=2)
    
    # Lines
    for i in range(10):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        color = (
            random.randint(100, 200),
            random.randint(100, 200),
            random.randint(100, 200)
        )
        draw.line([(x1, y1), (x2, y2)], fill=color, width=1)
    
    # Add some text overlay
    try:
        # Try to load a font, fallback to default if not available
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 36)
    except:
        font = ImageFont.load_default()
    
    text = "INTERCEPTED IMAGE"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    text_x = (width - text_width) // 2
    text_y = height - 80
    
    # Draw text with shadow
    draw.text((text_x + 2, text_y + 2), text, fill=(0, 0, 0, 128), font=font)
    draw.text((text_x, text_y), text, fill=(255, 255, 255), font=font)
    
    img.save(output_path, 'PNG')
    print(f"[+] Base image created: {output_path}")
    return output_path


def generate_challenge():
    """Generate the HIDDEN_LAYERS challenge files"""
    # Define paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    artifacts_dir = os.path.join(base_dir, 'artifacts')
    os.makedirs(artifacts_dir, exist_ok=True)
    
    # Challenge flag
    flag = "HQX{h1dd3n_1n_pl41n_s1ght_st3g0}"
    
    # Create base image
    temp_image = os.path.join(artifacts_dir, 'temp_base.png')
    create_base_image(800, 600, temp_image)
    
    # Hide flag in image
    output_image = os.path.join(artifacts_dir, 'mystery_image.png')
    LSBSteganography.hide_data_in_image(temp_image, flag, output_image)
    
    # Remove temp image
    if os.path.exists(temp_image):
        os.remove(temp_image)
    
    # Verify extraction
    print("\n[*] Verifying flag extraction...")
    extracted = extract_flag()
    if extracted == flag:
        print(f"[+] SUCCESS! Flag verified: {extracted}")
    else:
        print(f"[-] ERROR! Extracted: {extracted}")
    
    print("\n[+] Challenge generated successfully!")
    print(f"[+] Challenge files in: {artifacts_dir}")


def extract_flag():
    """
    Extract and return the flag from the challenge image
    Used for verification and testing
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    image_path = os.path.join(base_dir, 'artifacts', 'mystery_image.png')
    
    if not os.path.exists(image_path):
        return None
    
    try:
        extracted = LSBSteganography.extract_data_from_image(image_path)
        return extracted.strip()
    except Exception as e:
        print(f"Error extracting flag: {e}")
        return None


if __name__ == '__main__':
    print("=" * 60)
    print("HIDDEN_LAYERS - LSB Steganography Challenge Generator")
    print("=" * 60)
    generate_challenge()
