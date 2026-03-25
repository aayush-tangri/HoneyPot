import requests
import time

BASE = "http://127.0.0.1:8001"

# Simulate brute force
print("Simulating brute force...")
for i in range(20):
    requests.post(f"{BASE}/login", data={
        "username": "admin",
        "password": f"wrongpassword{i}"
    })
    time.sleep(0.1)

# Simulate IDOR enumeration
print("Simulating IDOR...")
for i in range(1, 6):
    requests.get(f"{BASE}/api/users/{i}")
    time.sleep(0.2)

# Simulate path traversal recon
print("Simulating recon...")
for path in ["/.env", "/wp-admin", "/wp-admin/admin-ajax.php"]:
    requests.get(f"{BASE}{path}")
    time.sleep(0.2)

# Simulate API abuse (high rate)
print("Simulating API abuse...")
for i in range(130):
    requests.get(f"{BASE}/api/admin/stats")

print("Done! Check your dashboard.")