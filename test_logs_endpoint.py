#!/usr/bin/env python
import requests
import json

# Login as admin
print("🔐 Logging in as admin...")
resp = requests.post('http://localhost:5000/api/auth/login', json={'email':'admin@example.com','password':'Admin123'})
data = resp.json()
token = data['access_token']
print(f"✓ Admin logged in: {data['user']['email']}")

# Fetch logs
print("\n📋 Fetching audit logs...")
logs_resp = requests.get('http://localhost:5000/api/logs', headers={'Authorization': f'Bearer {token}'})
print(f"Status: {logs_resp.status_code}")

logs_data = logs_resp.json()
if 'logs' in logs_data:
    logs = logs_data['logs']
    print(f"\n✓ Retrieved {len(logs)} log entries")
    
    if logs:
        print("\nRecent logs (last 5):")
        print("-" * 100)
        for log in logs[-5:]:
            ts = log.get('timestamp', 'N/A')
            event = log.get('event_type', 'N/A')
            user = log.get('user_id', 'N/A')
            endpoint = log.get('endpoint', 'N/A')
            ip = log.get('ip', 'N/A')
            print(f"{event:25} | User:{user:3} | {endpoint:30} | {ip:15}")
    else:
        print("No logs recorded yet")
else:
    print("✗ Error fetching logs:", logs_data)
