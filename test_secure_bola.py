import requests

BASE = 'http://localhost:5000'

# Reset
r = requests.post(f"{BASE}/api/setup/reset")
print('Reset:', r.status_code)

# Login as User1
r = requests.post(f"{BASE}/api/auth/login", json={"email":"user1@example.com","password":"Password123"})
print('\nLogin User1:', r.status_code)
if r.status_code != 200:
    print(r.text)
    exit(1)

token = r.json()['access_token']
headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

# Try to read Order 2 (belongs to User2)
print('\n>>> Try to access Order 2 (belongs to User2) as User1:')
r = requests.get(f"{BASE}/api/orders/2", headers=headers)
print(f"Status: {r.status_code}")
print(f"Response: {r.text[:300]}")

if r.status_code == 403:
    print("\n✓ SECURE: Server blocked cross-user access (403)")
elif r.status_code == 200:
    print("\n✗ VULNERABLE: Server allowed cross-user access (200)")
else:
    print(f"\n? Unexpected status: {r.status_code}")
