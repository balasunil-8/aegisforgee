# Manual LSB Extraction Guide

## Overview
This guide walks through **manual extraction** of hidden data from an image using LSB steganography. This is the educational approach to understand the underlying mechanics.

---

## Method 1: Using zsteg (Easiest)

### Installation
```bash
# Install Ruby (if not already installed)
sudo apt-get install ruby ruby-dev

# Install zsteg
sudo gem install zsteg
```

### Usage
```bash
# Basic scan
zsteg mystery_image.png

# Verbose output (all extraction methods)
zsteg -a mystery_image.png

# Extract specific channel
zsteg -e "b1,rgb,lsb,xy" mystery_image.png > output.txt
```

### Expected Output
```
b1,rgb,lsb,xy       .. text: "HQX{h1dd3n_1n_pl41n_s1ght_st3g0}"
```

**Time: 2 minutes**

---

## Method 2: Using StegSolve (Visual Analysis)

### Installation
```bash
# Download StegSolve
wget http://www.caesum.com/handbook/Stegsolve.jar

# Run StegSolve
java -jar Stegsolve.jar
```

### Usage Steps
1. **Open Image**: File → Open → Select `mystery_image.png`
2. **View Planes**: Use arrow keys to cycle through bit planes
   - Red plane 0 (LSB)
   - Green plane 0 (LSB)
   - Blue plane 0 (LSB)
3. **Extract Data**: Analyse → Data Extract
4. **Configure**:
   - Select all RGB checkboxes
   - Select "LSB First"
   - Order: Row, Column
   - Bit plane: 0
5. **Preview**: View extracted data in preview window
6. **Save**: Save extracted data to file

**Time: 5 minutes**

---

## Method 3: Using Python + PIL (Custom Script)

### Install Dependencies
```bash
pip3 install Pillow
```

### Quick Extraction Script
Create `extract.py`:
```python
from PIL import Image

def extract_lsb(image_path):
    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())
    
    # Extract LSB from each channel
    bits = ""
    for pixel in pixels:
        r, g, b = pixel
        bits += str(r & 1)
        bits += str(g & 1)
        bits += str(b & 1)
    
    # Convert to text
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            char = chr(int(byte, 2))
            if char.isprintable() or char in '\n\r':
                chars.append(char)
            else:
                break  # Stop at non-printable
    
    return ''.join(chars)

# Run extraction
flag = extract_lsb('mystery_image.png')
print(flag)
```

### Run
```bash
python3 extract.py
```

**Time: 5-10 minutes**

---

## Method 4: Using Online Tools

### StegOnline
1. Visit: https://stegonline.georgeom.net/
2. Upload `mystery_image.png`
3. Click "Go to Extract Data/LSB"
4. Configuration:
   - Select: RGB channels
   - Bit selection: 0 (LSB)
   - Extraction order: Row-major
5. Click "Extract"
6. View extracted data in output

**Time: 3 minutes**

---

## Method 5: Using Hex Editor (Advanced)

### Tools
- `xxd` (command line)
- `hexedit` (terminal UI)
- HxD (Windows GUI)
- 010 Editor (Commercial)

### Process
```bash
# View hex dump
xxd mystery_image.png | less

# Look at end of file (common hiding spot)
xxd mystery_image.png | tail -n 50

# Search for flag format
xxd mystery_image.png | grep -i "HQX"
```

### Analysis
- Look for patterns in LSB
- Check for appended data after PNG IEND chunk
- Analyze entropy distribution

**Note**: LSB data won't be visible in hex - this is for other steganography methods.

**Time: 20-30 minutes**

---

## Method 6: Using Stegseek (Password Cracking)

If the data is password-protected (not in this challenge):

### Installation
```bash
# Download from GitHub
wget https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb
sudo dpkg -i stegseek_0.6-1.deb
```

### Usage
```bash
# Crack password using wordlist
stegseek mystery_image.jpg rockyou.txt

# Extract with known password
stegseek --extract mystery_image.jpg password
```

**Not applicable to this challenge** (no password protection)

---

## Method 7: Manual Bit Extraction (Educational)

### Understanding the Process

#### Step 1: View First Pixel
```python
from PIL import Image

img = Image.open('mystery_image.png')
pixels = list(img.getdata())

# First pixel
r, g, b = pixels[0]
print(f"Pixel 0: RGB({r}, {g}, {b})")
```

#### Step 2: Extract LSB
```python
# Convert to binary
r_bin = format(r, '08b')
g_bin = format(g, '08b')
b_bin = format(b, '08b')

print(f"R: {r_bin} → LSB: {r & 1}")
print(f"G: {g_bin} → LSB: {g & 1}")
print(f"B: {b_bin} → LSB: {b & 1}")
```

#### Step 3: Collect Bits
```python
# Collect LSBs from multiple pixels
bits = []
for i in range(100):  # First 100 pixels
    r, g, b = pixels[i]
    bits.append(str(r & 1))
    bits.append(str(g & 1))
    bits.append(str(b & 1))

bit_string = ''.join(bits)
print(f"First 300 bits: {bit_string}")
```

#### Step 4: Convert to Text
```python
# Group into bytes and convert
message = ""
for i in range(0, len(bit_string), 8):
    byte = bit_string[i:i+8]
    if len(byte) == 8:
        char = chr(int(byte, 2))
        if char.isprintable():
            message += char
        else:
            break

print(f"Message: {message}")
```

**Time: 30-45 minutes (learning)**

---

## Verification

After extraction, verify you have the correct flag:

### Flag Format
```
HQX{...}
```

### Expected Flag
```
HQX{h1dd3n_1n_pl41n_s1ght_st3g0}
```

### Validation
- Starts with `HQX{`
- Ends with `}`
- Contains only alphanumeric and underscores
- Total length: 35 characters

---

## Troubleshooting

### Problem: zsteg shows no results
**Solution**: The image might be JPEG (zsteg only works with PNG/BMP)

### Problem: Extracted data is gibberish
**Possible causes**:
- Wrong extraction order (try BGR instead of RGB)
- Wrong bit plane (try MSB instead of LSB)
- Data is encrypted/encoded
- Wrong channel (try individual R, G, or B)

### Problem: EOF marker not found
**Solution**: Manually inspect first 100-200 characters of extracted data

### Problem: Python script crashes
**Possible causes**:
- Missing PIL/Pillow: `pip3 install Pillow`
- Wrong image path
- Corrupted image file

---

## Comparison of Methods

| Method | Difficulty | Time | Automation | Learning Value |
|--------|-----------|------|------------|----------------|
| zsteg | Easy | 2 min | High | Low |
| StegSolve | Easy | 5 min | Medium | Medium |
| Python Script | Medium | 10 min | High | High |
| Online Tools | Easy | 3 min | High | Low |
| Hex Editor | Hard | 30 min | Low | Medium |
| Manual Bits | Hard | 45 min | None | Very High |

---

## Recommended Approach for CTFs

1. **Quick scan**: `strings image.png | grep -i flag`
2. **Automated tools**: `zsteg -a image.png`
3. **Visual analysis**: StegSolve (if zsteg fails)
4. **Custom script**: Python (if specific extraction needed)
5. **Manual analysis**: Hex editor (last resort)

---

## Real-World Tools

### Professional Forensics
- **Autopsy** - Digital forensics platform
- **Sleuth Kit** - Forensic analysis tools
- **FTK Imager** - Commercial forensics
- **EnCase** - Enterprise forensics

### CTF-Specific
- **Aperi'Solve** - Automated stego solver
- **StegCracker** - Steghide password cracker
- **StegoVeritas** - Automated stego analysis

---

## Summary

For **HIDDEN_LAYERS** challenge:
1. **Fastest**: `zsteg mystery_image.png` (2 minutes)
2. **Most Educational**: Python manual extraction (45 minutes)
3. **Best for Learning**: Follow the full SOLUTION.md walkthrough

Choose the method that matches your goals:
- **CTF competition**: Use zsteg (speed)
- **Learning steganography**: Use Python script (understanding)
- **Forensics practice**: Use multiple tools (thoroughness)

Good luck! 🎯
