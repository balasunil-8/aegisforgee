# HIDDEN_LAYERS - Solution Walkthrough

## Challenge Overview

**Category:** Steganography  
**Difficulty:** Intermediate  
**Points:** 150  
**Flag:** `HQX{h1dd3n_1n_pl41n_s1ght_st3g0}`

This challenge demonstrates **LSB (Least Significant Bit) steganography**, one of the most common techniques for hiding data in images.

---

## What is Steganography?

**Steganography** is the art and science of hiding information within other information. Unlike cryptography (which makes data unreadable), steganography makes data *invisible* by hiding it inside innocent-looking files.

**Examples in history:**
- Ancient Greece: Messages tattooed on shaved heads, hidden when hair grew back
- WWII: Microdots containing photographs reduced to the size of a period
- Modern: Digital files hiding data in imperceptible ways

---

## Understanding LSB Steganography

### The Concept

Digital images are made of pixels. Each pixel in an RGB image has three color values (Red, Green, Blue), each ranging from 0-255.

**Example pixel:**
- Color: RGB(154, 87, 211)
- In binary: `10011010`, `01010111`, `11010011`
- The **rightmost bit** (LSB) has the least impact on the color

### Why LSB Works

Changing the LSB of a color value only changes it by ±1:
- RGB(154, 87, 211) → RGB(155, 86, 210)
- This difference is **imperceptible** to the human eye!

### How It Works

**Hiding data:**
1. Convert secret message to binary
2. Replace the LSB of each color channel with message bits
3. Save the modified image (looks identical!)

**Extracting data:**
1. Read the LSB from each color channel
2. Combine bits into bytes
3. Convert bytes to characters

**Visual representation:**
```
Original Pixel:    R: 10011010 (154)  G: 01010111 (87)   B: 11010011 (211)
                          ↓               ↓               ↓
LSB extracted:           [0]             [1]             [1]

Message bits:     0  1  1  0  1  0  0  0  (01101000 = 'h')
                  ↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓
Hidden in:        R  G  B  R  G  B  R  G  (of different pixels)
```

---

## Solution Method 1: Automated Tool (zsteg)

### Step 1: Install zsteg
```bash
gem install zsteg
```

### Step 2: Run zsteg on the image
```bash
zsteg mystery_image.png
```

**Expected output:**
```
b1,rgb,lsb,xy       .. text: "HQX{h1dd3n_1n_pl41n_s1ght_st3g0}"
```

**Explanation:**
- `b1` = 1 bit per channel
- `rgb` = RGB color channels
- `lsb` = Least Significant Bit
- `xy` = Row-major order (left-to-right, top-to-bottom)

### Step 3: Extract the flag
The flag is directly visible in the output: `HQX{h1dd3n_1n_pl41n_s1ght_st3g0}`

**Time to solve: ~2 minutes**

---

## Solution Method 2: Python Script (Custom)

### Step 1: Use the provided solve.py script
```bash
python3 solution/solve.py ../artifacts/mystery_image.png
```

### Step 2: Understand the code
The script:
1. Opens the image and converts to RGB
2. Extracts LSB from each pixel's R, G, B values
3. Combines bits into bytes
4. Converts bytes to ASCII characters
5. Looks for the EOF marker to stop extraction

**See `solution/solve.py` for full implementation.**

**Time to solve: ~5 minutes**

---

## Solution Method 3: Manual Extraction (Educational)

### Understanding the Binary

Let's manually extract the first few characters:

**First pixel RGB(120, 160, 200):**
- R: 120 = `01111000` → LSB: **0**
- G: 160 = `10100000` → LSB: **0**
- B: 200 = `11001000` → LSB: **0**

**Second pixel RGB(105, 87, 211):**
- R: 105 = `01101001` → LSB: **1**
- G: 87 = `01010111` → LSB: **1**
- B: 211 = `11010011` → LSB: **1**

**Third pixel RGB(154, 200, 112):**
- R: 154 = `10011010` → LSB: **0**
- G: 200 = `11001000` → LSB: **0**

**Collected bits:** `0 0 0 1 1 1 0 0` = `00011100` (wrong order)

Actually, bits are collected in order: `01001000` = 72 = 'H'

### Binary to ASCII Table (relevant chars)
```
01001000 = 72 = 'H'
01010001 = 81 = 'Q'
01011000 = 88 = 'X'
01111011 = 123 = '{'
01101000 = 104 = 'h'
00110001 = 49 = '1'
```

### Full Manual Process
1. Extract LSB from every pixel (R→G→B order)
2. Group bits into 8-bit bytes
3. Convert each byte to ASCII
4. Read until you see the flag pattern

**Time to solve: ~20-30 minutes (educational)**

---

## Solution Method 4: Online Tools

### StegOnline
1. Visit: https://stegonline.georgeom.net/
2. Upload `mystery_image.png`
3. Go to "Extract Data/LSB"
4. Check "RGB" and "LSB"
5. View extracted data

**Time to solve: ~3 minutes**

---

## Step-by-Step Walkthrough (Beginner-Friendly)

### Step 1: Reconnaissance
```bash
# Check file type
file mystery_image.png
# Output: PNG image data, 800 x 600, 8-bit/color RGB

# Check for obvious strings
strings mystery_image.png | grep -i "HQX"
# Output: (nothing - it's well hidden!)

# Check metadata
exiftool mystery_image.png
# Output: Basic PNG metadata, nothing suspicious
```

### Step 2: Steganography Analysis
```bash
# Try zsteg (the easiest method)
zsteg mystery_image.png
```

**Output shows:**
```
b1,rgb,lsb,xy       .. text: "HQX{h1dd3n_1n_pl41n_s1ght_st3g0}"
```

**Success!** The flag is: `HQX{h1dd3n_1n_pl41n_s1ght_st3g0}`

---

## Why This Works

### Pixel Capacity
- Image size: 800 × 600 = 480,000 pixels
- Each pixel has 3 channels (RGB)
- Total bits available: 480,000 × 3 = 1,440,000 bits
- Total bytes available: 1,440,000 ÷ 8 = 180,000 bytes
- Flag length: 35 characters = 280 bits
- **Capacity used: 0.02%** - Plenty of room!

### Visual Impact
The LSB change is so small that:
- Maximum color change: ±1 per channel
- Human eye cannot detect changes < 3-5 units
- The image looks **identical** to the original

---

## Key Takeaways

### What You Learned
1. **LSB steganography** is a powerful technique for hiding data
2. **Automated tools** like zsteg can quickly detect common steganography
3. **Custom scripts** give you full control over extraction
4. **Binary manipulation** is essential for digital forensics
5. **Data can hide in plain sight** - always look deeper!

### CTF Tips
- **Always try automated tools first** (zsteg, binwalk, exiftool)
- **Check all color planes** (R, G, B, and alpha if present)
- **Look for patterns** in LSB extraction
- **Try different bit planes** (not just LSB - try 2nd, 3rd bits)
- **Consider alternative orders** (BGR instead of RGB)

### Real-World Applications
- **Malware**: Hiding malicious payloads in images
- **Espionage**: Covert communication channels
- **Copyright**: Digital watermarking
- **Forensics**: Detecting hidden data in evidence

---

## Defense Against Steganography

### Detection Methods
1. **Statistical analysis** - LSB should be random in natural images
2. **Visual inspection** - Check individual bit planes
3. **File size analysis** - Compare to expected size
4. **Chi-square test** - Detect non-random distributions

### Prevention Methods
1. **Strip metadata** from all uploaded images
2. **Re-encode images** at lower quality (destroys LSB data)
3. **Monitor file sizes** for anomalies
4. **Use steganography detection tools** on uploads

---

## Further Learning

### Try These Challenges
- **picoCTF**: Information, Like Water
- **HackTheBox**: Unified
- **CryptoHack**: Steganography challenges

### Tools to Master
- `zsteg` - PNG/BMP LSB detection
- `steghide` - JPEG steganography
- `stegsolve` - Visual analysis
- `binwalk` - Embedded file detection

### Topics to Explore
- MSB steganography (Most Significant Bit)
- DCT coefficient steganography (JPEG)
- Audio steganography (WAV/MP3)
- Network steganography (packet timing)

---

## Flag

```
HQX{h1dd3n_1n_pl41n_s1ght_st3g0}
```

**Congratulations!** You've successfully extracted hidden data using LSB steganography!

---

## References

- [Wikipedia: Steganography](https://en.wikipedia.org/wiki/Steganography)
- [LSB Steganography Explained](https://www.geeksforgeeks.org/lsb-based-image-steganography-using-matlab/)
- [zsteg GitHub](https://github.com/zed-0xff/zsteg)
- [Digital Image Processing](https://www.imageprocessingplace.com/)

*Remember: With great power comes great responsibility. Use steganography ethically and legally!*
