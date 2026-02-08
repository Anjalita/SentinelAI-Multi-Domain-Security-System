import requests

# Test 1: Web detection
print("Testing web attack detection...")
response = requests.post(
    "http://localhost:8000/api/detect/web",
    json={"payload": "<script>alert('xss')</script>"}
)
print(f"XSS Detection: {response.json()}")

# Test 2: Safe input
response = requests.post(
    "http://localhost:8000/api/detect/web",
    json={"payload": "hello world"}
)
print(f"Safe input: {response.json()}")

# Test 3: Network attack simulation
print("\nTesting network IDS...")
response = requests.post(
    "http://localhost:8000/api/simulate/network-attack",
    params={"attack_type": "ssh_bruteforce"}
)
print(f"Network attack: {response.json()}")

# Test 4: Check alerts
print("\nChecking alerts...")
response = requests.get("http://localhost:8000/api/alerts")
print(f"Total alerts: {len(response.json()['alerts'])}")
