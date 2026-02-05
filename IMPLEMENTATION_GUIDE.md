# AegisForge Implementation Guide

This guide helps developers complete the remaining components of the AegisForge platform.

---

## 🔵 Implementing Blue Team Endpoints

### Overview
Blue Team endpoints are hardened versions of vulnerable (Red Team) endpoints that demonstrate security best practices.

### Implementation Pattern

```python
# File: aegisforge_blue.py

from flask import request, jsonify
from defenses import sanitize_sql_input, validate_url, add_security_headers

# Example 1: Hardened SQL Injection Endpoint
@app.route('/api/blue/injection/sqli/boolean', methods=['GET'])
def blue_sqli_boolean():
    """
    SECURE VERSION: Boolean-based SQL injection endpoint
    Security Controls:
    - Input sanitization
    - Parameterized queries
    - Error message suppression
    """
    username = request.args.get('username', '')
    
    # Defense 1: Input validation
    if not username or len(username) > 50:
        return {'ok': False, 'error': 'Invalid input'}, 400
    
    # Defense 2: Parameterized query
    query = "SELECT * FROM user WHERE username = ?"
    cursor = db.cursor()
    cursor.execute(query, (username,))
    results = cursor.fetchall()
    
    # Defense 3: Controlled error messages
    if results:
        return {
            'ok': True,
            'message': 'User found',
            'count': len(results),
            'security_note': 'Used parameterized query to prevent SQL injection'
        }
    else:
        return {
            'ok': True,
            'message': 'No results',
            'security_note': 'Input validated and sanitized'
        }

# Example 2: Hardened XSS Endpoint
@app.route('/api/blue/xss/reflected', methods=['GET'])
def blue_xss_reflected():
    """
    SECURE VERSION: Reflected XSS endpoint
    Security Controls:
    - Output encoding
    - Content-Type enforcement
    - CSP headers
    """
    from defenses import sanitize_xss_input
    
    name = request.args.get('name', 'Guest')
    
    # Defense: HTML encode output
    safe_name = sanitize_xss_input(name)
    
    response = {
        'ok': True,
        'message': f'Hello, {safe_name}',
        'security_note': 'Output HTML-encoded to prevent XSS'
    }
    
    return response

# Example 3: Hardened SSRF Endpoint
@app.route('/api/blue/ssrf/fetch', methods=['POST'])
def blue_ssrf_fetch():
    """
    SECURE VERSION: SSRF endpoint
    Security Controls:
    - URL validation
    - Allowlist of domains
    - Network segmentation
    """
    from defenses import validate_url
    
    data = request.get_json() or {}
    url = data.get('url', '')
    
    # Defense: Validate URL and check for SSRF
    is_valid, error_msg = validate_url(url, allow_private=False)
    
    if not is_valid:
        return {
            'ok': False,
            'error': error_msg,
            'security_note': 'URL validation prevented SSRF attempt'
        }, 403
    
    # Defense: Domain allowlist
    allowed_domains = ['example.com', 'api.public-service.com']
    from urllib.parse import urlparse
    domain = urlparse(url).netloc
    
    if domain not in allowed_domains:
        return {
            'ok': False,
            'error': 'Domain not in allowlist',
            'security_note': 'Only whitelisted domains are allowed'
        }, 403
    
    # Safe to fetch
    import requests
    try:
        response = requests.get(url, timeout=5)
        return {
            'ok': True,
            'data': response.text[:500],
            'security_note': 'URL validated against allowlist'
        }
    except Exception as e:
        return {'ok': False, 'error': 'Fetch failed'}, 500
```

### Step-by-Step Guide

1. **Create `aegisforge_blue.py`**
   ```bash
   touch aegisforge_blue.py
   ```

2. **Import necessary modules**
   ```python
   from flask import Blueprint, request, jsonify
   from defenses import (
       sanitize_sql_input, sanitize_xss_input, sanitize_command_input,
       validate_url, validate_file_path, validate_positive_integer,
       check_rate_limit, add_security_headers
   )
   ```

3. **Create Blueprint**
   ```python
   blue_team = Blueprint('blue_team', __name__, url_prefix='/api/blue')
   ```

4. **Implement each endpoint**
   - Copy the vulnerable endpoint code
   - Add appropriate defense controls
   - Add security notes to responses
   - Document which defense is applied

5. **Register Blueprint in `aegisforge_api.py`**
   ```python
   from aegisforge_blue import blue_team
   app.register_blueprint(blue_team)
   ```

### Defense Selection Guide

| Vulnerability Type | Defense Module | Key Functions |
|-------------------|----------------|---------------|
| SQL Injection | `input_validator` | `sanitize_sql_input()` + parameterized queries |
| XSS | `input_validator` | `sanitize_xss_input()` |
| Command Injection | `input_validator` | `sanitize_command_input()` |
| SSRF | `input_validator` | `validate_url()` |
| Path Traversal | `input_validator` | `validate_file_path()` |
| Rate Limit Bypass | `rate_limiter` | `check_rate_limit()` |
| Missing Headers | `security_headers` | `add_security_headers()` |

---

## 🎯 Adding Missing OWASP Vulnerabilities

### OWASP Web 2021 - A04: Insecure Design

```python
@app.route('/api/insecure-design/discount-abuse', methods=['POST'])
def insecure_design_discount():
    """
    VULNERABLE: Business logic flaw allowing discount abuse
    
    Flaw: Can apply discount multiple times
    """
    data = request.get_json() or {}
    order_id = data.get('order_id')
    discount_code = data.get('discount_code')
    
    # VULNERABLE: No check if discount already applied
    # Users can apply discount multiple times
    
    return {'ok': True, 'discount_applied': True}

# BLUE TEAM VERSION
@app.route('/api/blue/insecure-design/discount-abuse', methods=['POST'])
def blue_insecure_design_discount():
    """
    SECURE: Discount can only be applied once per order
    """
    data = request.get_json() or {}
    order_id = data.get('order_id')
    discount_code = data.get('discount_code')
    
    # Check if discount already applied
    # (In real app, check database)
    if check_discount_used(order_id):
        return {
            'ok': False,
            'error': 'Discount already applied to this order',
            'security_note': 'Business logic enforced'
        }, 400
    
    return {'ok': True, 'discount_applied': True}
```

### OWASP Web 2025 - A03: Supply Chain

```python
@app.route('/api/supply-chain/vulnerable-dep', methods=['GET'])
def supply_chain_vuln():
    """
    DEMONSTRATION: Shows how to check for vulnerable dependencies
    """
    import pkg_resources
    
    vulnerable_packages = {
        'requests': '2.6.0',  # Known vulnerable version
        'urllib3': '1.24.0',
    }
    
    installed = []
    for pkg in vulnerable_packages:
        try:
            version = pkg_resources.get_distribution(pkg).version
            installed.append({
                'package': pkg,
                'installed_version': version,
                'vulnerable_version': vulnerable_packages[pkg],
                'is_vulnerable': version == vulnerable_packages[pkg]
            })
        except:
            pass
    
    return {
        'ok': True,
        'dependencies': installed,
        'recommendation': 'Always keep dependencies updated'
    }
```

### OWASP API 2023 - API1: BOLA (Already exists, needs labeling)

```python
# Just add better documentation and labels
@app.route('/api/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    """
    VULNERABLE: API1 - Broken Object Level Authorization (BOLA)
    
    Issue: No ownership check - any user can access any order
    OWASP: API1:2023
    """
    # Existing vulnerable code
    pass

@app.route('/api/blue/orders/<int:order_id>', methods=['GET'])
@jwt_required()
def blue_get_order(order_id):
    """
    SECURE: API1 - Proper Object Level Authorization
    
    Security: Verifies user owns the order before returning
    OWASP: API1:2023 - Remediated
    """
    current_user = get_jwt_identity()
    
    # Check ownership
    order = Order.query.get(order_id)
    if not order or order.user_id != current_user:
        return {'ok': False, 'error': 'Not authorized'}, 403
    
    return {'ok': True, 'order': order.to_dict()}
```

---

## 🔧 Tool Integration Examples

### Creating Postman Collection

Create `collections/AegisForge_Complete.postman_collection.json`:

```json
{
  "info": {
    "name": "AegisForge - Complete Collection",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Mode Switching",
      "item": [
        {
          "name": "Get Mode Status",
          "request": {
            "method": "GET",
            "url": "{{base_url}}/api/mode/status"
          }
        },
        {
          "name": "Toggle Mode",
          "request": {
            "method": "POST",
            "url": "{{base_url}}/api/mode/toggle"
          }
        }
      ]
    },
    {
      "name": "CTF Challenges",
      "item": [
        {
          "name": "Get AREA64 Challenge",
          "request": {
            "method": "GET",
            "url": "{{base_url}}/api/ctf/challenges/area64"
          }
        },
        {
          "name": "Submit Flag",
          "request": {
            "method": "POST",
            "url": "{{base_url}}/api/ctf/challenges/area64/verify",
            "body": {
              "mode": "raw",
              "raw": "{\"flag\": \"HQX{...}\"}"
            }
          }
        }
      ]
    }
  ]
}
```

### SQLMap Examples

Create `docs/sqlmap_examples.md`:

```markdown
# SQLMap Testing Guide

## Boolean-based Blind SQL Injection
```bash
sqlmap -u "http://localhost:5000/api/injection/sqli/boolean?username=test" \
  -p username \
  --batch \
  --level=5 \
  --risk=3 \
  --technique=B
```

## Time-based Blind SQL Injection
```bash
sqlmap -u "http://localhost:5000/api/injection/sqli/time?id=1" \
  -p id \
  --batch \
  --technique=T
```
```

---

## 🧪 Testing Implementation

### Unit Tests

Create `tests/test_blue_team.py`:

```python
import unittest
from aegisforge_api import app
from defenses import sanitize_sql_input, validate_url

class TestBlueTean(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
    
    def test_sql_sanitization(self):
        """Test SQL input sanitization"""
        malicious = "admin' OR '1'='1"
        sanitized = sanitize_sql_input(malicious)
        self.assertNotIn("'", sanitized)
    
    def test_ssrf_prevention(self):
        """Test SSRF URL validation"""
        is_valid, msg = validate_url("http://localhost:5000/api/health")
        self.assertFalse(is_valid)
        self.assertIn("Localhost", msg)
    
    def test_blue_endpoint(self):
        """Test blue team endpoint returns security notes"""
        response = self.app.get('/api/blue/injection/sqli/boolean?username=test')
        data = response.get_json()
        self.assertIn('security_note', data)

if __name__ == '__main__':
    unittest.main()
```

---

## 📊 Implementing Leaderboard

### Database Model

```python
class CTFScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    challenge_id = db.Column(db.String(50))
    points = db.Column(db.Integer)
    solved_at = db.Column(db.DateTime, default=datetime.utcnow)
    hints_used = db.Column(db.Integer, default=0)
```

### Leaderboard Endpoint

```python
@app.route('/api/ctf/leaderboard', methods=['GET'])
def ctf_leaderboard():
    """Get CTF leaderboard"""
    scores = db.session.query(
        User.username,
        db.func.sum(CTFScore.points).label('total_points'),
        db.func.count(CTFScore.id).label('challenges_solved')
    ).join(CTFScore).group_by(User.id).order_by(
        db.desc('total_points')
    ).limit(10).all()
    
    return {
        'ok': True,
        'leaderboard': [
            {
                'rank': idx + 1,
                'username': score[0],
                'points': score[1],
                'solved': score[2]
            }
            for idx, score in enumerate(scores)
        ]
    }
```

---

## 🎯 Priority Implementation Order

1. **Blue Team Endpoints** (4 hours)
   - Start with SQL injection, XSS, SSRF
   - Then authentication and access control
   - Finally business logic flaws

2. **OWASP Gap Fill** (3 hours)
   - Add A04, A05, A06 endpoints
   - Label existing API vulnerabilities
   - Create mapping document

3. **Tool Integration** (2 hours)
   - Postman collection
   - SQLMap examples
   - Burp Suite configs

4. **Testing** (2 hours)
   - Unit tests for defense modules
   - Integration tests for endpoints
   - CTF challenge verification tests

5. **Documentation** (2 hours)
   - Screenshots
   - Video script
   - API reference

**Total Estimated Time**: 13 hours to complete remaining work

---

**Last Updated**: 2026-02-05
