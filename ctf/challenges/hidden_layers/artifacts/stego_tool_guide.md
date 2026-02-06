# Steganography Tools Guide

## What is Steganography?

Steganography is the practice of concealing messages or information within other non-secret data. In digital steganography, information is hidden within digital media files such as images, audio, or video.

## Common Steganography Techniques

### 1. LSB (Least Significant Bit) Steganography
- **Method:** Replaces the least significant bit of each byte in the carrier file
- **Detection:** Changes are imperceptible to human eye/ear
- **Best for:** Images, audio files
- **Capacity:** High (up to 12.5% of file size)

### 2. EOF (End of File) Steganography
- **Method:** Appends data after the file's natural end marker
- **Detection:** File size analysis, hex editor inspection
- **Best for:** Any file format with defined EOF markers
- **Capacity:** Unlimited (but suspicious if too large)

### 3. Metadata Steganography
- **Method:** Hides data in file metadata/EXIF data
- **Detection:** Metadata extraction tools
- **Best for:** Images (JPEG, PNG), documents
- **Capacity:** Limited

## Essential Steganography Tools

### 1. zsteg (Ruby)
**Installation:**
```bash
gem install zsteg
```

**Usage:**
```bash
# Detect steganography in PNG/BMP
zsteg mystery_image.png

# Verbose output
zsteg -a mystery_image.png

# Extract specific LSB
zsteg -e b1,rgb,lsb,xy mystery_image.png
```

**Best for:** PNG and BMP files, LSB detection

---

### 2. steghide (C++)
**Installation:**
```bash
sudo apt-get install steghide
```

**Usage:**
```bash
# Extract hidden data
steghide extract -sf mystery_image.jpg

# Embed data
steghide embed -cf image.jpg -ef secret.txt

# Get info without extracting
steghide info mystery_image.jpg
```

**Best for:** JPEG and BMP files, password-protected data

---

### 3. stegsolve (Java)
**Installation:**
```bash
# Download from: http://www.caesum.com/handbook/Stegsolve.jar
wget http://www.caesum.com/handbook/Stegsolve.jar
java -jar Stegsolve.jar
```

**Usage:**
- Open image in GUI
- Use arrow keys to cycle through color planes
- Analyze -> Data Extract for LSB extraction
- Analyze -> Frame Browser for GIF/multi-frame images

**Best for:** Visual analysis, multiple file formats

---

### 4. stegcracker (Python)
**Installation:**
```bash
pip3 install stegcracker
```

**Usage:**
```bash
# Brute force steghide password
stegcracker image.jpg wordlist.txt
```

**Best for:** Password-protected steghide files

---

### 5. binwalk (Python)
**Installation:**
```bash
sudo apt-get install binwalk
```

**Usage:**
```bash
# Scan for embedded files
binwalk mystery_image.png

# Extract embedded files
binwalk -e mystery_image.png

# Scan with entropy analysis
binwalk -E mystery_image.png
```

**Best for:** Detecting hidden archives, embedded files

---

### 6. exiftool (Perl)
**Installation:**
```bash
sudo apt-get install exiftool
```

**Usage:**
```bash
# View all metadata
exiftool mystery_image.png

# View specific tags
exiftool -Comment -Description mystery_image.png

# Remove all metadata
exiftool -all= mystery_image.png
```

**Best for:** Metadata analysis and extraction

---

### 7. Python + PIL/Pillow
**Installation:**
```bash
pip3 install Pillow
```

**Usage (LSB Extraction):**
```python
from PIL import Image

def extract_lsb(image_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())
    
    binary_data = ""
    for pixel in pixels:
        r, g, b = pixel[:3]  # Handle RGBA
        binary_data += str(r & 1)
        binary_data += str(g & 1)
        binary_data += str(b & 1)
    
    # Convert binary to text
    chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    message = ''.join(chr(int(byte, 2)) for byte in chars if len(byte) == 8)
    return message

print(extract_lsb('mystery_image.png'))
```

**Best for:** Custom extraction scripts, learning

---

### 8. Online Tools

#### StegOnline
- **URL:** https://stegonline.georgeom.net/
- **Features:** LSB extraction, color plane analysis, browser-based
- **Best for:** Quick analysis without installing tools

#### Forensically
- **URL:** https://29a.ch/photo-forensics/
- **Features:** ELA, metadata, clone detection
- **Best for:** Image forensics and manipulation detection

#### Aperi'Solve
- **URL:** https://www.aperisolve.com/
- **Features:** Runs multiple stego tools automatically
- **Best for:** Comprehensive automated analysis

---

## Analysis Workflow

### Step 1: Initial Reconnaissance
```bash
# Check file type
file mystery_image.png

# Check metadata
exiftool mystery_image.png

# Check file size and structure
ls -lh mystery_image.png
```

### Step 2: Automated Detection
```bash
# Run zsteg (PNG/BMP)
zsteg mystery_image.png

# Run binwalk
binwalk mystery_image.png

# Check for embedded archives
binwalk -e mystery_image.png
```

### Step 3: Manual Analysis
```bash
# Visual analysis with stegsolve
java -jar Stegsolve.jar mystery_image.png

# Custom Python script
python3 extract_lsb.py mystery_image.png

# Hex editor inspection
xxd mystery_image.png | less
```

### Step 4: Extraction
```bash
# Extract with appropriate tool based on findings
# For LSB: zsteg, custom script, or stegsolve
# For steghide: steghide extract
# For embedded files: binwalk -e
```

---

## LSB Steganography Deep Dive

### How LSB Works

Each pixel in an RGB image has 3 color channels (Red, Green, Blue), each with a value from 0-255 (8 bits).

**Example:**
- Pixel: RGB(154, 87, 211)
- Binary: `10011010`, `01010111`, `11010011`
- LSBs: `0`, `1`, `1` (rightmost bit of each)

### Hiding Data
1. Convert message to binary: "HI" → `01001000 01001001`
2. Replace LSB of each color channel:
   - R: `10011010` → `1001101[0]` (LSB from message)
   - G: `01010111` → `0101011[1]` (LSB from message)
   - B: `11010011` → `1101001[0]` (LSB from message)
3. Result: RGB(154, 87, 210) - Visually identical!

### Extracting Data
1. Read LSB from each color channel
2. Combine bits: `010 010 001...`
3. Group into bytes: `01001000 01001001`
4. Convert to ASCII: "HI"

### Detection Methods
- **Statistical analysis:** Compare LSB distribution to expected randomness
- **Visual inspection:** Some implementations show patterns in LSB plane
- **Chi-square test:** Detect non-random LSB patterns
- **File size analysis:** Stego images may be slightly larger

---

## Tips for CTF Challenges

1. **Always check strings first:**
   ```bash
   strings mystery_image.png | grep -i "flag\|HQX{"
   ```

2. **Try automatic tools before manual:**
   - zsteg is fast and effective for PNG files
   - binwalk catches many common techniques

3. **Check all color planes:**
   - Sometimes data is only in one channel (R, G, or B)
   - Use stegsolve to cycle through planes

4. **Look for patterns:**
   - MSB might be used instead of LSB
   - Data might be in specific bit planes (2nd, 3rd bit, etc.)

5. **Check file headers and trailers:**
   ```bash
   xxd mystery_image.png | head -n 20  # Header
   xxd mystery_image.png | tail -n 20  # Trailer
   ```

6. **Try different extraction orders:**
   - RGB vs BGR
   - Row-major vs column-major
   - Reverse bit order

---

## Resources

- **Books:**
  - "Hiding in Plain Sight" by Eric Cole
  - "Digital Watermarking and Steganography" by Cox et al.

- **CTF Practice:**
  - picoCTF
  - HackTheBox
  - TryHackMe

- **Tools Repository:**
  - https://github.com/DominicBreuker/stego-toolkit
  - https://github.com/bannsec/stegoVeritas

Good luck with your steganography journey!
