# VulnShop API - Integrated Setup Guide

## 🚀 Quick Start

Your VulnShop API is now fully integrated! The frontend and backend run as a single unified application.

### Option 1: One-Command Launch (Recommended)

**Windows (PowerShell):**
```powershell
cd C:\vuln_api_testing
.\LaunchVulnShop.ps1
```

**Windows (Command Prompt):**
```cmd
cd C:\vuln_api_testing
LaunchVulnShop.bat
```

**Linux/Mac:**
```bash
cd vuln_api_testing
python start_vulnshop.py
```

### Option 2: Manual Launch

**Activate virtual environment:**
```bash
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Windows (Command Prompt)
.venv\Scripts\activate.bat

# Linux/Mac
source .venv/bin/activate
```

**Start the API:**
```bash
python vulnshop.py
```

**Access the dashboard:**
- Open browser: `http://localhost:5000/`
- Dashboard will automatically connect to the backend API
- All data is live and reflects the database state

---

## 📊 Dashboard Features

### Live Backend Data Tab
- **Connected Users**: Shows all registered users in the database
- **Available Products**: Lists inventory with prices and stock
- **Current Orders**: View all orders and their status
- **Database Summary**: Real-time connection status

### Postman Test Guide Tab
- **Detailed Test Explanations**: Learn what each vulnerability does
- **Expected Results**: See vulnerable vs. secure responses
- **Attack Examples**: Understand the real-world impact

### OWASP Vulnerabilities Tab
- **Complete Reference**: All 10 OWASP API Top 10 (2023)
- **Affected Endpoints**: Which parts of the API are vulnerable
- **Fix Descriptions**: How to patch each vulnerability
- **Severity Levels**: CRITICAL, HIGH, MEDIUM, LOW

### Attack Demonstrations Tab
- **Step-by-Step Guides**: Execute each attack with Postman
- **Real vs. Secure**: Compare vulnerable and secure responses
- **Video-Ready**: Each demo takes 2-3 minutes

### Teaching Guide Tab
- **60-Minute Lesson Plan**: Complete classroom curriculum
- **Live Demo Script**: Exact words to say during presentation
- **Student Exercises**: Hands-on activities and challenges
- **Troubleshooting**: Common problems and solutions

---

## 🧪 Using with Postman

### Import the Collections

1. **Open Postman**
2. **Import Collection**: File → Import → Select `VulnShop_Collection.json`
3. **Import Environment**: File → Import → Select `VulnShop_Environment.json`
4. **Set Base URL**: Environment should be set to `http://localhost:5000`

### Run Tests

The collection includes pre-built tests for all vulnerabilities:

```
📁 VulnShop API
  ├── 00 - Setup
  │   ├── Reset DB
  │   └── Health Check
  ├── 01 - Auth
  │   ├── Login User1
  │   └── Login Admin
  ├── 02 - API1 BOLA
  │   ├── Read other user's order
  │   └── Read other user's profile
  ├── 03 - API2 Authentication
  │   ├── Missing token rejection
  │   └── Invalid token acceptance
  ... and more
```

---

## 🔒 Architecture Changes

### Before (Two Servers)
- Backend: Flask on port 5000
- Frontend: Five Server on port 7412
- CORS issues, separate startup, port conflicts

### After (Unified)
- **Single Server**: Flask on port 5000
- **Dashboard URL**: `http://localhost:5000/`
- **API Routes**: `http://localhost:5000/api/*`
- **Benefits**: 
  - No port conflicts ✓
  - No CORS issues ✓
  - Single startup command ✓
  - Professional integrated UI ✓

---

## 📋 New Endpoints Added

The dashboard needs these endpoints to display live data:

```
GET /api/users              → List all users (dashboard info)
GET /api/products           → List all products (already existed)
GET /api/orders             → List all orders (dashboard info)
GET /                       → Dashboard HTML (NEW - serves the dashboard)
```

---

## 🎓 Teaching Your First Class

### Quick 60-Minute Demo

1. **0-5 min**: Show the dashboard "Live Backend Data" tab
2. **5-15 min**: Navigate to "Attack Demonstrations"
3. **15-25 min**: Pick BOLA (easiest vulnerability)
   - Show the attack step in dashboard guide
   - Switch to Postman and execute it
   - Show the vulnerable response
4. **25-35 min**: Show the secure version
   - `python secure_vulnshop.py`
   - Run same attack
   - Show it's blocked (403 Forbidden)
5. **35-45 min**: Pick another vulnerability (Mass Assignment)
   - Follow same pattern
6. **45-60 min**: Q&A and wrap-up

### Student Exercise

Give students a goal: *"Access Order 2 while logged in as User1"*

1. Have them use the "Attack Demonstrations" tab as a guide
2. Open Postman
3. Execute the attack
4. Discuss the result

---

## 🛠 Troubleshooting

### Dashboard Shows "Failed to Connect to API"
- ✓ Check that Flask is running
- ✓ Open terminal and verify no errors
- ✓ Try `http://localhost:5000/api/health` in browser

### Port 5000 Already in Use
```bash
# Find what's using it
lsof -i :5000  # Linux/Mac

# Kill the process
kill -9 <PID>  # Linux/Mac

# Windows (in PowerShell as admin)
Get-Process | Where-Object {$_.Port -eq 5000}
Stop-Process -Id <PID> -Force
```

### Virtual Environment Issues
```bash
# Recreate venv
python -m venv .venv

# Install requirements
.venv\Scripts\activate.bat  # Windows
pip install -r requirements.txt
```

---

## 📊 Generate Report

Create a comprehensive security report:

```bash
python generate_report.py
```

Output:
- Console: Formatted report in terminal
- File: `vulnshop_report.json` for data analysis
- Metrics: Test coverage and security score

---

## 🔄 Switch Between Vulnerable & Secure

**Vulnerable (Default):**
```bash
python vulnshop.py
```

**Secure Version:**
```bash
python secure_vulnshop.py
```

Then refresh your browser at `http://localhost:5000/`

---

## 📁 File Structure

```
vuln_api_testing/
├── vulnshop.py                      ← Main API (vulnerable version)
├── secure_vulnshop.py               ← Secure reference implementation
├── Dashboard_Interactive.html       ← Served at http://localhost:5000/
├── start_vulnshop.py                ← Automated startup script
├── LaunchVulnShop.ps1               ← PowerShell launcher
├── LaunchVulnShop.bat               ← Windows batch launcher
├── VulnShop_Collection.json         ← Postman tests
├── VulnShop_Environment.json        ← Postman environment
├── requirements.txt                 ← Python dependencies
├── generate_report.py               ← Report generator
└── README.md                        ← Original documentation
```

---

## 🎯 Learning Path

### Beginner (20 minutes)
1. Open dashboard
2. Review "OWASP Vulnerabilities" tab
3. Read 5-minute summary of each API vulnerability

### Intermediate (60 minutes)
1. Follow "60-Minute Lesson Plan" in Teaching Guide
2. Execute 3-4 attacks from Attack Demonstrations
3. Compare vulnerable vs. secure responses

### Advanced (3+ hours)
1. Review `vulnshop.py` source code
2. Try writing fixes in `secure_vulnshop.py`
3. Create your own test API with these vulnerabilities
4. Present findings to team

---

## 📞 Support

**If the API won't start:**
- Check Python version: `python --version` (need 3.8+)
- Check dependencies: `pip list`
- Check for errors in console output
- Try: `python -m py_compile vulnshop.py`

**If dashboard doesn't load any data:**
- Ensure API is running: visit `http://localhost:5000/api/health`
- Check browser console for errors (F12)
- Refresh the page (Ctrl+R)

**For production deployment:**
- Never use the vulnerable version in production!
- Use `secure_vulnshop.py` as a starting point
- Add proper authentication, validation, rate limiting
- Use a production WSGI server (gunicorn, etc.)

---

## ✅ Quick Checklist

- [ ] Virtual environment activated
- [ ] All dependencies installed (`pip install -r requirements.txt`)
- [ ] Started with `python vulnshop.py` or `LaunchVulnShop.ps1`
- [ ] Dashboard accessible at `http://localhost:5000/`
- [ ] API responding to `http://localhost:5000/api/health`
- [ ] Live data showing users, products, orders
- [ ] Postman collection imported and configured
- [ ] Ready to demo API vulnerabilities!

---

## 🎓 Happy Teaching!

You're all set to teach OWASP API Top 10 security to your students, team, or yourself.

**Next Steps:**
1. Start the API: `python vulnshop.py`
2. Open dashboard: `http://localhost:5000/`
3. Pick your first vulnerability
4. Execute the attack using Postman
5. Explain the vulnerability and its fix
6. Show them the secure version!

---

*Last Updated: February 5, 2026*
*For educational purposes only*
