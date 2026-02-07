# SecureBank Troubleshooting Guide

Common issues and solutions for SecureBank setup and usage.

---

## 📋 Table of Contents

- [Installation Issues](#installation-issues)
- [API Connection Issues](#api-connection-issues)
- [Database Issues](#database-issues)
- [Authentication Issues](#authentication-issues)
- [CORS Issues](#cors-issues)
- [Port Conflicts](#port-conflicts)
- [Browser Issues](#browser-issues)
- [Performance Issues](#performance-issues)
- [FAQ](#frequently-asked-questions)

---

## Installation Issues

### Python Version Error

**Problem**: `python: command not found` or version mismatch

**Solution**:
```bash
# Check Python version
python --version
python3 --version

# Use python3 if needed
python3 seed_data.py
python3 securebank_red_api.py
```

**Requirements**: Python 3.8 or higher is required.

### Missing Dependencies

**Problem**: `ModuleNotFoundError: No module named 'flask'`

**Solution**:
```bash
# Navigate to project root
cd /home/runner/work/aegisforgee/aegisforgee

# Install dependencies
pip install -r requirements.txt

# Or install individually
pip install Flask Flask-CORS
```

### Permission Denied

**Problem**: `PermissionError` when creating database

**Solution**:
```bash
# Check directory permissions
ls -la backend/apps/securebank/

# Create with sudo if needed (Linux/Mac)
sudo python seed_data.py

# Or change permissions
chmod +w backend/apps/securebank/
```

---

## API Connection Issues

### Cannot Connect to API

**Problem**: `Failed to fetch` or `Connection refused`

**Checklist**:
1. ✅ Is the API running? Check terminal for "Running on http://..."
2. ✅ Correct port? Red Team=5000, Blue Team=5001
3. ✅ Correct URL in utils.js?
4. ✅ Firewall blocking? Check firewall settings

**Solution**:
```bash
# Check if port is in use
lsof -i :5000  # Linux/Mac
netstat -ano | findstr :5000  # Windows

# Restart API
Ctrl+C (stop)
python securebank_red_api.py  # restart
```

### API Timeout

**Problem**: Requests take too long or timeout

**Possible Causes**:
- Database locked
- Too many simultaneous requests
- Server overloaded

**Solution**:
```bash
# Restart API with debug mode
python securebank_red_api.py

# Check database
sqlite3 backend/apps/securebank/securebank.db
.tables
.quit

# If database is locked, restart terminal
```

### 404 Not Found

**Problem**: `404 Not Found` on API endpoints

**Check**:
- URL path: `/api/red/securebank/login` (not `/api/securebank/login`)
- HTTP method: POST for login (not GET)
- API is running on correct port

---

## Database Issues

### Database Not Found

**Problem**: `no such table: bank_users`

**Solution**:
```bash
# Recreate database
cd backend/apps/securebank
python seed_data.py
```

### Database Locked

**Problem**: `database is locked`

**Solution**:
```bash
# Stop all API instances
Ctrl+C on all terminals

# Delete database (will lose data)
rm backend/apps/securebank/securebank.db

# Recreate
python seed_data.py
```

### Seed Data Not Loading

**Problem**: Login fails with correct credentials

**Solution**:
```bash
# Verify data exists
sqlite3 backend/apps/securebank/securebank.db
SELECT * FROM bank_users;
.quit

# If empty, reseed
python seed_data.py
```

---

## Authentication Issues

### Login Fails (Red Team)

**Problem**: Cannot login even with SQL injection

**Checklist**:
1. ✅ API running on port 5000?
2. ✅ Database seeded with users?
3. ✅ CORS enabled?
4. ✅ Browser console for errors?

**Test**:
```bash
# Manual API test
curl -X POST http://localhost:5000/api/red/securebank/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
```

### Session Not Persisting

**Problem**: Logged out after page refresh

**Causes**:
- Cookies disabled in browser
- Incognito/Private mode
- CORS credentials not set
- Session storage cleared

**Solution**:
- Enable cookies in browser
- Use normal browser mode
- Check `credentials: 'include'` in utils.js
- Don't clear browser storage manually

### CSRF Token Issues (Blue Team)

**Problem**: "Invalid CSRF token" error

**Solution**:
1. Check `/csrf-token` endpoint is accessible
2. Token stored in localStorage
3. Token sent in `X-CSRF-Token` header
4. Clear localStorage and try again:
   ```javascript
   localStorage.clear()
   ```

---

## CORS Issues

### CORS Policy Blocked

**Problem**: `Access-Control-Allow-Origin` error

**Common Causes**:
- Opening HTML file directly (file:// protocol)
- API not allowing origin
- Missing credentials

**Solution**:

**Option 1**: Use a local web server
```bash
# Python built-in server
cd frontend/apps/securebank/red
python -m http.server 8000

# Then open: http://localhost:8000/login.html
```

**Option 2**: Browser extension
- Install "CORS Unblock" extension (development only!)
- Enable for localhost

**Option 3**: Check API CORS config
```python
# In API file, ensure:
CORS(app, supports_credentials=True, resources={
    r"/api/red/securebank/*": {"origins": "*"}
})
```

### Cookies Not Sent

**Problem**: Session not maintained across requests

**Solution**:
```javascript
// In utils.js, ensure:
const defaultOptions = {
    credentials: 'include',  // This line is critical
    headers: {
        'Content-Type': 'application/json'
    }
};
```

---

## Port Conflicts

### Port Already in Use

**Problem**: `Address already in use` when starting API

**Solution**:

**Find and kill process**:
```bash
# Linux/Mac
lsof -ti:5000 | xargs kill -9
lsof -ti:5001 | xargs kill -9

# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

**Use different port**:
```python
# In API file, change:
app.run(debug=True, port=5002)  # Use 5002 instead

# Update utils.js:
RED_TEAM_BASE_URL: 'http://localhost:5002/api/red/securebank'
```

---

## Browser Issues

### JavaScript Errors

**Problem**: `Uncaught ReferenceError` or similar

**Solutions**:
1. Check browser console (F12)
2. Ensure all JS files are loaded:
   ```html
   <script src="js/utils.js"></script>
   <script src="js/auth.js"></script>
   ```
3. Check file paths are correct
4. Hard refresh: Ctrl+Shift+R (Ctrl+F5 on Windows)

### Styling Not Loading

**Problem**: Page looks unstyled

**Solutions**:
1. Check CSS files are linked:
   ```html
   <link rel="stylesheet" href="css/banking.css">
   ```
2. Check file paths
3. Clear browser cache
4. Open DevTools (F12) → Network tab → Check CSS files load

### Browser Compatibility

**Tested Browsers**:
- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+

**Known Issues**:
- Internet Explorer: Not supported
- Old browsers: May have JavaScript compatibility issues

---

## Performance Issues

### Slow Page Load

**Causes**:
- Large database
- Many concurrent users
- Slow machine

**Solutions**:
```bash
# Reduce sample data
# Edit seed_data.py, reduce number of transactions

# Use production mode (no debug)
app.run(debug=False, port=5000)

# Enable database Write-Ahead Logging
conn.execute('PRAGMA journal_mode=WAL')
```

### Slow Transfers (Race Condition Test)

**Expected**: Race condition tests may be slow due to locking in Blue Team

**Solution**: This is intentional! Blue Team uses locks to prevent race conditions.

---

## Frequently Asked Questions

### Q: Can I use a real database instead of SQLite?

**A**: Yes! Modify `database.py` to use PostgreSQL or MySQL.

```python
# Example for PostgreSQL
import psycopg2
DATABASE_URL = "postgresql://user:password@localhost/securebank"
```

### Q: How do I reset everything?

**A**:
```bash
# Stop all APIs
# Delete database
rm backend/apps/securebank/securebank.db

# Clear browser data
# In browser: Clear cookies and localStorage

# Reseed database
python seed_data.py

# Restart APIs
```

### Q: Can I deploy this to production?

**A**: **NO!** Red Team version has intentional vulnerabilities. Blue Team is educational, not production-ready. Additional hardening needed:
- Use HTTPS
- Use bcrypt for passwords
- Add rate limiting
- Use environment variables for secrets
- Add logging and monitoring
- Regular security audits

### Q: Why is SQL injection working in Blue Team?

**A**: It shouldn't! If it is:
1. Make sure you're testing Blue Team (port 5001)
2. Check `securebank_blue_api.py` uses parameterized queries
3. Report as bug if confirmed

### Q: How do I test race conditions effectively?

**A**: Use the "Rapid Fire" button in Red Team transfer page, or:
```bash
# Using curl in parallel
for i in {1..10}; do
  curl -X POST http://localhost:5000/api/red/securebank/transfer \
    -H "Content-Type: application/json" \
    -H "Cookie: session=<your-session>" \
    -d '{"from_account":"1234567890","to_account":"2345678901","amount":50}' &
done
```

### Q: Where are the logs?

**A**: 
- Flask logs: Terminal where you ran the API
- Browser logs: Browser Developer Tools (F12) → Console
- Database queries: Enable Flask SQL logging

### Q: Can I add more vulnerabilities?

**A**: Yes! Fork the repository and add:
- Path traversal
- Command injection
- XXE
- SSRF
- Broken authentication
- Sensitive data exposure

### Q: How do I contribute?

**A**: 
1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit pull request
5. Follow contribution guidelines

---

## 🐛 Reporting Bugs

If you find a bug not covered here:

1. **Check**: Is it in the Red Team (intentional) or Blue Team (bug)?
2. **Search**: Look for existing issues on GitHub
3. **Report**: Create new issue with:
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Browser/OS/Python version
   - Screenshots if applicable

---

## 💬 Getting Help

- **Documentation**: Read all guides in `docs/apps/securebank/`
- **Issues**: Search GitHub Issues
- **Community**: Join AegisForge discussions
- **Email**: support@aegisforge.io

---

## 📌 Quick Reference

**Common Commands**:
```bash
# Setup
python seed_data.py

# Run Red Team
python securebank_red_api.py

# Run Blue Team  
python securebank_blue_api.py

# Test API
curl http://localhost:5000/api/red/securebank/session

# Check database
sqlite3 securebank.db "SELECT * FROM bank_users;"

# Find port usage
lsof -i :5000  # Mac/Linux
netstat -ano | findstr :5000  # Windows
```

**Test Credentials**:
- alice / password123
- bob / securepass456
- admin / admin123

**API URLs**:
- Red Team: `http://localhost:5000/api/red/securebank/`
- Blue Team: `http://localhost:5001/api/blue/securebank/`

---

**Still having issues? Contact support or create a GitHub issue!**
