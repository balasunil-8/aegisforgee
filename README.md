# 🛡️ AegisForge - Ultimate Security Learning Platform

**Master Offensive & Defensive Security**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Flask](https://img.shields.io/badge/Flask-3.0.2-green.svg)](https://flask.palletsprojects.com/)

---

## 🎯 What is AegisForge?

Professional-grade security testing platform for **Red Team (offensive)** and **Blue Team (defensive)** training.

### ✨ Key Features

- ✅ **Dual-Mode Learning**: Toggle between vulnerable and hardened endpoints
- ✅ **Complete OWASP Coverage**: Web 2021/2025 + API 2023
- ✅ **CTF Arena**: 5 real-world challenges (100-300pts)
- ✅ **AI Detection**: ML-based attack classification
- ✅ **Tool Integration**: Postman, Burp, SQLMap, ZAP, FFUF
- ✅ **Cloud Ready**: Railway, Render, Docker

---

## 🚀 Quick Start

```bash
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python aegisforge_api.py
```

Visit: `http://localhost:5000`

---

## 🎮 Dual-Mode System

### 🔴 Red Team (Offensive)
```bash
curl -X POST http://localhost:5000/api/mode/set -H "Content-Type: application/json" -d '{"mode":"red"}'
```

### 🔵 Blue Team (Defensive)
```bash
curl -X POST http://localhost:5000/api/mode/set -H "Content-Type: application/json" -d '{"mode":"blue"}'
```

---

## 📖 Vulnerabilities

50+ vulnerabilities including:
- SQL Injection (Boolean, Time, UNION)
- XSS (Reflected, Stored, DOM)
- IDOR, BFLA, Mass Assignment
- SSRF, Command Injection, XXE
- Deserialization, Race Conditions
- Authentication & Access Control flaws

---

## 🏆 CTF Challenges

1. **AREA64** (100pts) - Base64 crypto
2. **SmallE** (100pts) - RSA attack  
3. **Hidden Layers** (100pts) - Steganography
4. **Paper Script** (300pts) - PDF forensics
5. **Synthetic Stacks** (300pts) - Multi-layer

---

## 🔧 Tools

- **Postman**: Import collection
- **Burp Suite**: Configure proxy
- **SQLMap**: `sqlmap -u "http://localhost:5000/api/injection/sqli/boolean?username=test"`
- **ZAP**: `zap-cli quick-scan http://localhost:5000`
- **FFUF**: `ffuf -u http://localhost:5000/FUZZ -w wordlist.txt`

---

## ⚠️ Legal Notice

**Educational use only** in isolated environments. Never test systems without authorization.

---

## 📚 Documentation

See: `POSTMAN_GUIDE.md`, `BURP_SUITE_GUIDE.md`, `SQLMAP_GUIDE.md`, `OWASP_ZAP_GUIDE.md`, `FFUF_GUIDE.md`

---

**Happy Ethical Hacking! 🛡️**
