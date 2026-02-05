import requests
import json

BASE='http://localhost:5000'
# login
r = requests.post(f"{BASE}/api/auth/login", json={"email":"user1@example.com","password":"Password123"})
print('login', r.status_code, r.text)
if r.status_code!=200:
    raise SystemExit(1)
token = r.json()['access_token']
headers = {'Authorization': f'Bearer {token}', 'Content-Type':'application/json'}
# create order
r2 = requests.post(f"{BASE}/api/orders", json={"product_id":2, "quantity":1, "price":1}, headers=headers)
print('create', r2.status_code, r2.text)
