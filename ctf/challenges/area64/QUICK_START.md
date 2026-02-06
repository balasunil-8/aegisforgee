# 🎯 AREA64 - Quick Start Guide

## 🚀 Get Started in 30 Seconds

This is a beginner-friendly cryptography challenge about Base64 encoding.

### Step 1: Read the Challenge
```bash
cat artifacts/encoded_message.txt
```

### Step 2: Find the Encoded String
Look for this line in the message:
```
SFFYe2I0czM2NF8xc19uMHRfZW5jcnlwdGkwbl82NGMwZDN9
```

### Step 3: Decode It
**Option A - Command Line:**
```bash
echo "SFFYe2I0czM2NF8xc19uMHRfZW5jcnlwdGkwbl82NGMwZDN9" | base64 -d
```

**Option B - Python:**
```python
import base64
print(base64.b64decode("SFFYe2I0czM2NF8xc19uMHRfZW5jcnlwdGkwbl82NGMwZDN9").decode())
```

**Option C - Automated:**
```bash
python3 solution/solve.py
```

### Step 4: Get the Flag
The decoded message is your flag! Submit it to complete the challenge.

---

## 📚 Learn More

- **Full Instructions:** See `artifacts/instructions.txt`
- **Complete Solution:** See `solution/SOLUTION.md`
- **Need a Hint?** Check `solution/hints.json`

---

## 💡 Key Concepts

**This challenge teaches:**
- The difference between encoding and encryption
- How Base64 encoding works
- Basic command-line tools
- Pattern recognition in CTF challenges

**Remember:** Base64 is NOT encryption - it's just encoding!

---

## 🎓 Challenge Details

- **Category:** Cryptography
- **Difficulty:** Beginner
- **Points:** 100
- **Time:** 10-15 minutes
- **Skills:** Base64, command-line tools, critical thinking

---

## 🛠️ For Challenge Administrators

### Generate Challenge Files:
```bash
python3 challenge.py
```

### Run Tests:
```bash
pytest tests/test_area64.py -v
```

### Verify Everything Works:
```bash
python3 solution/solve.py
```

---

**Good luck and happy hacking! 🚀**
