# HIDDEN_LAYERS - Steganography Challenge

## Challenge Information
- **Category:** Steganography
- **Difficulty:** Intermediate
- **Points:** 150
- **Flag Format:** `HQX{...}`

## Scenario

Your intelligence agency has intercepted an image file sent between two suspected cyber criminals. The file appears to be an innocent landscape photo, but your forensic analysis tools detected anomalies in the image data.

The suspects are known to use steganography techniques to hide sensitive information in plain sight. Your mission is to extract the hidden data from this image and recover the flag.

**Intercepted Message Fragment:**
```
"The package is ready. Check the layers, but look carefully - 
it's hidden where the eye can't see. The bits tell the story."
```

## What is Steganography?

**Steganography** is the practice of concealing information within other non-secret data. Unlike encryption (which scrambles data), steganography hides the very existence of the message.

Common steganography techniques include:
- **LSB (Least Significant Bit)** - Hiding data in the least significant bits of image pixels
- **EOF (End of File)** - Appending data after a file's normal end marker
- **Metadata** - Hiding data in file metadata/headers
- **Whitespace** - Using invisible characters in text files

## What is LSB Steganography?

LSB steganography is one of the most popular image steganography techniques. It works by replacing the least significant bit of each pixel's color value with a bit of the hidden message.

**Why it works:**
- Changing the LSB of a pixel value only changes the color by ±1
- This change is imperceptible to the human eye
- Example: RGB(154, 87, 211) vs RGB(155, 86, 210) - can you tell the difference?

**How it works:**
1. Convert secret message to binary
2. Replace LSB of each pixel component (R, G, B) with message bits
3. The image looks identical but contains hidden data

## What You'll Learn

- Understanding LSB steganography techniques
- Digital forensics and image analysis
- Binary data manipulation
- Using steganography analysis tools
- Python image processing with PIL/Pillow

## Files Provided

- `mystery_image.png` - The intercepted image file
- `instructions.txt` - Brief instructions from the intercept
- `stego_tool_guide.md` - Guide to steganography analysis tools

## Your Mission

Extract the hidden flag from `mystery_image.png`. The flag is hidden using LSB steganography.

**Hints available:**
- Hint 1 (15 points): What encoding method might be used?
- Hint 2 (30 points): Which tools can extract LSB data?
- Hint 3 (50 points): How to decode the extracted bits?

## Tools You Might Need

- **Python + PIL/Pillow** - For custom extraction scripts
- **zsteg** - Ruby-based steganography detection tool
- **stegsolve** - Java-based image analysis tool
- **Hex editors** - For manual analysis

Good luck, agent! The fate of the operation depends on you.

---

*Remember: In steganography, the message is hidden in the "layers" of data that our eyes cannot perceive.*
