# VulnShop API - Quick Start & Reference

## 🚀 One-Command Start

### Windows (Best for Windows)
```powershell
# PowerShell
cd C:\vuln_api_testing
.\LaunchVulnShop.ps1
```

### Windows (Alternative)
```cmd
cd C:\vuln_api_testing
LaunchVulnShop.bat
```

### Linux / macOS
```bash
cd vuln_api_testing
python start_vulnshop.py
```

---

## 📖 What Happens When You Start

✅ Checks Python version
✅ Verifies virtual environment
✅ Confirms all packages installed
✅ Initializes database with test data
✅ Starts Flask API on port 5000
✅ **Dashboard automatically opens in browser**
✅ Shows colorful startup messages

---

## 🎯 Once It's Running

### Access the Dashboard
```
http://localhost:5000/
```

### Tabs Available
1. **Live Backend Data** - View real DB (users, products, orders)
2. **Postman Test Guide** - Learn each vulnerability
3. **OWASP Vulnerabilities** - Reference all 10 APIs
4. **Attack Demonstrations** - Step-by-step exploits
5. **Teaching Guide** - Lesson plans & exercises

### API Health Check
```
http://localhost:5000/api/health
```
Should return:
```json
{"ok": true, "service": "VulnShop API", "time": 1234567890}
```

---

## 🧪 Quick Test with Postman

### 1. Import Collections
- File → Import → `VulnShop_Collection.json`
- File → Import → `VulnShop_Environment.json`

### 2. Run First Test
- Expand: "00 - Setup"
- Click: "Health Check"
- Click: Send
- See: 200 OK response

### 3. Try an Attack
- Expand: "02 - API1 BOLA"
- Click: "Read another user's order"
- Click: Send
- See: 200 OK + data you shouldn't see (VULNERABLE!)

---

## 📊 Key URLs

| URL | What You Get |
|-----|--------------|
| `http://localhost:5000/` | Dashboard (main page) |
| `http://localhost:5000/api/health` | API status |
| `http://localhost:5000/api/users` | All users list |
| `http://localhost:5000/api/products` | All products |
| `http://localhost:5000/api/orders` | All orders |

---

## 🛑 Stop the API

Press **Ctrl+C** in the terminal where it's running.

You'll see:
```
Shutting down VulnShop API...
```

---

## 🔄 Test Vulnerable vs Secure

### See the Vulnerabilities:
```bash
python vulnshop.py
```

### See How It's Fixed:
```bash
python secure_vulnshop.py
```

Run same attacks - now they're blocked! (403 Forbidden)

---

## 🎓 Demo Ideas (Copy-Paste These)

### 5-Minute Demo
1. Start: `python vulnshop.py`
2. Click "Attack Demonstrations" tab
3. Find "BOLA - Read Someone Else's Order"
4. Follow steps with Postman
5. Show the results
6. Explain: "No permission check = exploit"

### 15-Minute Demo
1. Show Dashboard Live Data (3 min)
2. Run BOLA attack (4 min)
3. Run Mass Assignment attack (4 min)
4. Explain impacts (4 min)

### Full 60-Minute Class
1. Follow "Teaching Guide" tab → "60-Minute Lesson Plan"
2. It has exact timing and talking points

---

## ⚡ Pro Tips

- Dashboard shows LIVE data from the database
- Each attack from dashboard has exact Postman steps
- Teaching Guide tab has complete lesson plans ready to use
- Refresh browser to see new orders/users
- Database resets with Postman "00 - Setup → Reset DB"

---

## 🚨 Troubleshooting

**Dashboard shows "Offline" indicator?**
- API might not be fully started yet, wait 2-3 seconds
- Try visiting `http://localhost:5000/api/health` directly

**Port 5000 already in use?**
```bash
# Find what's using it (Windows PowerShell as admin):
Get-Process | Where-Object {$_.Port -eq 5000}

# Kill it:
Stop-Process -Id <PID> -Force
```

**Virtual environment issues?**
```bash
# Recreate:
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

**Postman returns 401?**
- Did you run "00 - Setup → Login User1" first?
- Copy the token to {{token}} variable?
- Try logging in again

---

## 📝 Files You Need

```
vulnshop.py                    ← Start this with "python vulnshop.py"
Dashboard_Interactive.html     ← Served at http://localhost:5000/
VulnShop_Collection.json       ← Import into Postman
requirements.txt              ← Already installed
```

---

## ✅ Success Checklist

- [ ] Started with `python vulnshop.py` or launcher
- [ ] No errors in terminal
- [ ] Dashboard opened automatically (or you opened it manually)
- [ ] Dashboard shows green "Online ✓" indicator
- [ ] Live data showing: 3 users, 3 products, 2 orders
- [ ] Can click all tabs without errors
- [ ] Ready to run Postman tests!

---

## 🎯 Next: Run Your First Attack

1. **Open Dashboard** (already open)
2. **Click Tab**: "Attack Demonstrations"
3. **Find**: "BOLA - Read Someone Else's Order"
4. **Open Postman** and import collection
5. **Follow the steps** in the dashboard guide
6. **See the vulnerability** live!

---

**That's it! You're all set to teach or learn OWASP API security.** 🔒

For full documentation, see:
- [INTEGRATED_SETUP_GUIDE.md](INTEGRATED_SETUP_GUIDE.md) - Complete guide
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - All endpoints & attacks
- Dashboard Teaching Guide tab - Lesson plans ready to use

