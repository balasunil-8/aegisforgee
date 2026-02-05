#!/usr/bin/env python3
"""
Quick test script to verify vulnerable endpoints are working
"""
import sys
import json
from securityforge_api import app

# Create a test client
client = app.test_client()

print("Testing VULNERABLE Endpoints...")
print("=" * 70)

# Test 1: /api/search with SQL injection payload
print("\n1. Testing /api/search (SQL Injection)")
print("-" * 70)
response = client.get('/api/search?q=test')
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json, indent=2)}")

# Test 2: /api/config (Config Exposure)
print("\n2. Testing /api/config (Config Exposure)")
print("-" * 70)
response = client.get('/api/config')
print(f"Status: {response.status_code}")
if response.status_code == 200:
    print(f"Response: {json.dumps(response.json, indent=2)}")
else:
    print(f"Error: {response.data}")

# Test 3: /api/comments (Stored XSS)
print("\n3. Testing /api/comments GET (Stored XSS)")
print("-" * 70)
response = client.get('/api/comments')
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json, indent=2)}")

# Test 4: /api/display-message (Reflected XSS)
print("\n4. Testing /api/display-message (Reflected XSS)")
print("-" * 70)
response = client.get('/api/display-message?msg=<script>alert(1)</script>')
print(f"Status: {response.status_code}")
print(f"Response: {response.data.decode()}")

# Test 5: /api/users/1 (BOLA)
print("\n5. Testing /api/users/1 (BOLA)")
print("-" * 70)
response = client.get('/api/users/1')
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json, indent=2)}")

# Test 6: /api/products (Eval Injection)
print("\n6. Testing /api/products (Eval Injection)")
print("-" * 70)
response = client.get('/api/products?filter=<1000')
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json, indent=2)}")

# Test 7: /api/fetch-resource (SSRF)
print("\n7. Testing /api/fetch-resource (SSRF)")
print("-" * 70)
response = client.post('/api/fetch-resource', json={'url': 'http://example.com'})
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json, indent=2)}")

# Test 8: /api/weak-auth (Weak Auth)
print("\n8. Testing /api/weak-auth (Weak Auth)")
print("-" * 70)
response = client.post('/api/weak-auth', json={'username': 'admin', 'password': 'password'})
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json, indent=2)}")

# Test 9: /api/users/1/orders (BOLA on Orders)
print("\n9. Testing /api/users/1/orders (BOLA on Orders)")
print("-" * 70)
response = client.get('/api/users/1/orders')
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json, indent=2)}")

print("\n" + "=" * 70)
print("✓ All endpoint tests completed!")
