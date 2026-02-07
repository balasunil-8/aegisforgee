#!/usr/bin/env python3
"""
LSB Steganography Extractor
Automated solution for HIDDEN_LAYERS CTF challenge
"""

import sys
from PIL import Image


def extract_lsb_data(image_path):
    """
    Extract hidden data from image using LSB steganography
    
    Args:
        image_path: Path to the stego image
        
    Returns:
        Extracted message as string
    """
    try:
        # Open and convert image to RGB
        img = Image.open(image_path)
        img = img.convert('RGB')
        
        print(f"[*] Image size: {img.width}x{img.height}")
        print(f"[*] Total pixels: {img.width * img.height:,}")
        
        # Get all pixel data
        pixels = list(img.getdata())
        
        # Extract LSB from each color channel
        binary_data = ""
        for pixel in pixels:
            r, g, b = pixel
            binary_data += str(r & 1)  # Extract LSB from Red
            binary_data += str(g & 1)  # Extract LSB from Green
            binary_data += str(b & 1)  # Extract LSB from Blue
        
        print(f"[*] Extracted {len(binary_data):,} bits")
        
        # Look for EOF marker (1111111111111110)
        eof_marker = '1111111111111110'
        eof_pos = binary_data.find(eof_marker)
        
        if eof_pos != -1:
            print(f"[*] EOF marker found at bit position {eof_pos}")
            binary_data = binary_data[:eof_pos]
        else:
            print("[!] Warning: No EOF marker found, extracting all data")
        
        # Convert binary to text
        chars = []
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
                char_code = int(byte, 2)
                # Only add printable ASCII characters
                if 32 <= char_code <= 126:
                    chars.append(chr(char_code))
                elif char_code == 10:  # newline
                    chars.append('\n')
                elif char_code == 13:  # carriage return
                    chars.append('\r')
        
        message = ''.join(chars)
        return message
        
    except FileNotFoundError:
        print(f"[-] Error: File not found: {image_path}")
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def display_binary_visualization(image_path, num_pixels=5):
    """
    Display binary visualization of first few pixels for educational purposes
    """
    img = Image.open(image_path)
    img = img.convert('RGB')
    pixels = list(img.getdata())[:num_pixels]
    
    print("\n" + "=" * 70)
    print("BINARY VISUALIZATION (First few pixels)")
    print("=" * 70)
    
    collected_bits = []
    for i, pixel in enumerate(pixels):
        r, g, b = pixel
        r_bin = format(r, '08b')
        g_bin = format(g, '08b')
        b_bin = format(b, '08b')
        
        r_lsb = r & 1
        g_lsb = g & 1
        b_lsb = b & 1
        
        collected_bits.extend([r_lsb, g_lsb, b_lsb])
        
        print(f"\nPixel {i+1}: RGB({r}, {g}, {b})")
        print(f"  R: {r_bin} → LSB: {r_lsb}")
        print(f"  G: {g_bin} → LSB: {g_lsb}")
        print(f"  B: {b_bin} → LSB: {b_lsb}")
    
    # Show how bits form characters
    print("\n" + "-" * 70)
    print("RECONSTRUCTING CHARACTERS FROM LSB:")
    print("-" * 70)
    
    for i in range(0, len(collected_bits), 8):
        if i + 8 <= len(collected_bits):
            byte_bits = collected_bits[i:i+8]
            byte_str = ''.join(str(b) for b in byte_bits)
            char_code = int(byte_str, 2)
            if 32 <= char_code <= 126:
                char = chr(char_code)
                print(f"Bits {i//8 + 1}: {byte_str} = {char_code:3d} = '{char}'")


def main():
    print("=" * 70)
    print("LSB STEGANOGRAPHY EXTRACTOR")
    print("HIDDEN_LAYERS CTF Challenge Solution")
    print("=" * 70)
    
    # Get image path from command line or use default
    if len(sys.argv) > 1:
        image_path = sys.argv[1]
    else:
        image_path = '../artifacts/mystery_image.png'
    
    print(f"\n[*] Target image: {image_path}")
    
    # Display binary visualization for educational purposes
    try:
        display_binary_visualization(image_path)
    except Exception as e:
        print(f"[!] Could not display visualization: {e}")
    
    # Extract hidden data
    print("\n" + "=" * 70)
    print("EXTRACTING HIDDEN DATA")
    print("=" * 70 + "\n")
    
    message = extract_lsb_data(image_path)
    
    if message:
        print("\n" + "=" * 70)
        print("EXTRACTED MESSAGE:")
        print("=" * 70)
        print(message)
        print("=" * 70)
        
        # Check if flag is in the message
        if 'HQX{' in message:
            # Extract the flag
            start = message.find('HQX{')
            end = message.find('}', start) + 1
            flag = message[start:end]
            print("\n[+] FLAG FOUND!")
            print(f"[+] {flag}")
        else:
            print("\n[!] Flag not found in extracted data")
    else:
        print("\n[-] Failed to extract data")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
