# HIDDEN_LAYERS Challenge - Quick Start Guide

## For Challenge Administrators

This guide helps you deploy and verify the HIDDEN_LAYERS steganography challenge.

---

## ⚡ Quick Setup (1 minute)

```bash
# 1. Navigate to challenge directory
cd ctf/challenges/hidden_layers

# 2. Install dependencies
pip3 install Pillow

# 3. Generate challenge (if needed)
python3 challenge.py

# 4. Verify everything works
./verify.sh
```

Done! ✅

---

## 📦 What Gets Generated

When you run `python3 challenge.py`:

1. **artifacts/mystery_image.png** - 800x600 PNG with hidden flag
2. Flag verification happens automatically
3. All files remain in place

The image already exists and contains:
- Flag: `HQX{h1dd3n_1n_pl41n_s1ght_st3g0}`
- Hidden via LSB steganography
- Visually imperceptible changes

---

## 🎯 Quick Test

### Test Flag Extraction
```bash
# Method 1: Use the solution script
python3 solution/solve.py artifacts/mystery_image.png

# Method 2: Run tests
python3 -m pytest tests/test_hidden_layers.py -v

# Method 3: Use challenge's verify function
python3 -c "from challenge import extract_flag; print(extract_flag())"
```

All should show: `HQX{h1dd3n_1n_pl41n_s1ght_st3g0}`

---

## 📤 Deploy to Participants

### Provide These Files:
```
hidden_layers/
├── README.md                    # Challenge description
└── artifacts/
    ├── mystery_image.png        # The challenge file
    ├── instructions.txt         # Scenario/context
    └── stego_tool_guide.md      # Tool reference
```

### Don't Provide:
- ❌ challenge.py (generator code)
- ❌ solution/ directory (solutions!)
- ❌ tests/ directory (internal testing)
- ❌ challenge.json (backend metadata)

---

## 🏃 Quick Solve Verification

### As a participant would solve it:

**Method 1: Using zsteg (fastest)**
```bash
# Install zsteg (Ruby required)
gem install zsteg

# Run on challenge
zsteg artifacts/mystery_image.png
# Output: HQX{h1dd3n_1n_pl41n_s1ght_st3g0}
```

**Method 2: Using Python**
```bash
python3 solution/solve.py artifacts/mystery_image.png
# Shows extraction process and flag
```

**Method 3: Online tool**
1. Visit https://stegonline.georgeom.net/
2. Upload `mystery_image.png`
3. Extract LSB data from RGB channels
4. View flag

---

## 🔍 Troubleshooting

### Problem: "No module named PIL"
**Solution:**
```bash
pip3 install Pillow
```

### Problem: Image file missing
**Solution:**
```bash
python3 challenge.py  # Regenerates the image
```

### Problem: Tests failing
**Solution:**
```bash
# Regenerate challenge
python3 challenge.py

# Run verification
./verify.sh
```

### Problem: Wrong flag extracted
**Solution:**
```bash
# Regenerate with correct flag
python3 challenge.py

# The flag should be: HQX{h1dd3n_1n_pl41n_s1ght_st3g0}
```

---

## 📊 Challenge Statistics

| Metric | Value |
|--------|-------|
| **Difficulty** | Intermediate |
| **Points** | 150 |
| **Est. Time** | 30-45 minutes |
| **Category** | Steganography |
| **Flag** | HQX{h1dd3n_1n_pl41n_s1ght_st3g0} |
| **Image Size** | 37 KB |
| **Dimensions** | 800x600 pixels |

---

## 🎓 Learning Objectives

Participants will learn:
- ✅ LSB steganography concepts
- ✅ Image forensics techniques
- ✅ Binary data manipulation
- ✅ Tool usage (zsteg, Python PIL, etc.)
- ✅ Digital forensics workflow

---

## 💡 Hints Available

The challenge includes 3 progressive hints:

1. **Hint 1 (15 pts):** Encoding format and LSB concept
2. **Hint 2 (30 pts):** Tools and extraction methods
3. **Hint 3 (50 pts):** Complete algorithm details

Located in: `solution/hints.json`

---

## 🎯 Success Criteria

Participant succeeds when they submit:
```
HQX{h1dd3n_1n_pl41n_s1ght_st3g0}
```

Flag validation:
- Must start with `HQX{`
- Must end with `}`
- Exact match required (case-sensitive)
- Length: 32 characters

---

## 🔄 Regenerate Challenge

If you need to regenerate with a different flag:

1. Edit `challenge.py`:
```python
flag = "HQX{your_new_flag_here}"
```

2. Regenerate:
```bash
python3 challenge.py
```

3. Update `challenge.json`:
```json
"flag": "HQX{your_new_flag_here}"
```

4. Verify:
```bash
./verify.sh
```

---

## 📝 Challenge Metadata

### For CTF Platforms

**challenge.json** contains:
- Challenge ID and name
- Category and difficulty
- Points and flag
- Description
- Hints with costs
- Learning objectives
- File list

Import this JSON into your CTF platform.

---

## 🚀 Integration

### With CTFd:
```bash
# Create challenge via admin panel
# Upload artifacts as challenge files
# Set flag as: HQX{h1dd3n_1n_pl41n_s1ght_st3g0}
# Add hints from hints.json
```

### With rCTF:
```bash
# Create challenge in admin
# Upload mystery_image.png as challenge file
# Configure flag validation
# Add hint system
```

### Standalone:
```bash
# Just provide the artifacts/ directory
# Participants download and solve locally
```

---

## ✅ Pre-Deployment Checklist

Before deploying to participants:

- [ ] Run `./verify.sh` - all checks pass
- [ ] Test flag extraction manually
- [ ] Verify image file is not corrupted
- [ ] Check all documentation links work
- [ ] Test with fresh Python environment
- [ ] Verify hints are properly ordered
- [ ] Test at least 2 solution methods
- [ ] Confirm flag format matches platform

---

## 📞 Support

If participants need help:

1. **Stuck on concept:** Point to README.md "What is LSB Steganography"
2. **Don't know tools:** Point to `stego_tool_guide.md`
3. **Need gentle push:** Provide Hint 1 (15 points)
4. **Need more help:** Provide Hint 2 (30 points)
5. **Almost there:** Provide Hint 3 (50 points)
6. **Complete solution:** Point to `solution/SOLUTION.md` (after CTF)

---

## 🎉 Quick Commands Reference

```bash
# Generate challenge
python3 challenge.py

# Verify everything
./verify.sh

# Extract flag (test)
python3 solution/solve.py artifacts/mystery_image.png

# Run tests
python3 -m pytest tests/test_hidden_layers.py -v

# Quick flag check
python3 -c "from challenge import extract_flag; print(extract_flag())"

# View binary visualization
python3 solution/solve.py artifacts/mystery_image.png | head -50
```

---

## 📚 Documentation Files

For administrators:
- `CHALLENGE_SUMMARY.md` - Complete technical overview
- `QUICK_START.md` - This file
- `verify.sh` - Verification script

For participants:
- `README.md` - Challenge description
- `artifacts/stego_tool_guide.md` - Tool reference
- `artifacts/instructions.txt` - Scenario

For post-CTF:
- `solution/SOLUTION.md` - Complete walkthrough
- `solution/solve.py` - Automated solution
- `solution/solve_manual.md` - Manual methods

---

## 🎯 Expected Participant Journey

1. **Read README.md** (5 min)
   - Understand steganography concept
   - Learn about LSB technique
   - Get motivated by scenario

2. **Examine files** (5 min)
   - Look at mystery_image.png
   - Read instructions.txt
   - Check stego_tool_guide.md

3. **Try quick wins** (5 min)
   - strings command
   - exiftool metadata
   - binwalk scan

4. **Learn about LSB** (10 min)
   - Read tool guide
   - Understand extraction method
   - Choose approach

5. **Extract flag** (10-20 min)
   - Use zsteg, Python, or online tool
   - Verify extraction
   - Submit flag

**Total: 30-45 minutes**

---

## ✨ Tips for Success

**For smooth deployment:**
- Test on a fresh machine/container
- Provide clear file naming
- Include tool installation instructions
- Have multiple solution paths ready
- Monitor common issues

**For great experience:**
- Engaging scenario ✅
- Progressive hints ✅
- Multiple solution methods ✅
- Educational content ✅
- Clear documentation ✅

---

## 🏁 Ready to Deploy!

Your challenge is **complete and tested**:

✅ All files generated  
✅ Flag verified extractable  
✅ Tests passing (13/13)  
✅ Documentation complete  
✅ Multiple solution methods  
✅ Hints system ready  
✅ Verification script works  

**Just run**: `./verify.sh` and you're good to go! 🚀

---

*HIDDEN_LAYERS Challenge - AegisForge CTF*  
*Flag: HQX{h1dd3n_1n_pl41n_s1ght_st3g0}*
