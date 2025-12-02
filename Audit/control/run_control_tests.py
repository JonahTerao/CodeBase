import subprocess
import json
import requests

print("=== CONTROL TESTS ===")
print("Running automated and manual tests...\n")

# 1. Run Bandit (Static Analysis)
print("1. Running Bandit static analysis...")
try:
    result = subprocess.run(
        ['bandit', '-r', '.', '-f', 'json', '-o', 'control/bandit_results.json'],
        capture_output=True,
        text=True
    )
    print(f"   Bandit completed with {result.returncode}")
    
    # Parse results
    with open('control/bandit_results.json', 'r') as f:
        bandit_data = json.load(f)
    
    print(f"   Findings: {bandit_data.get('metrics', {}).get('_totals', {}).get('SEVERITY.HIGH', 0)} High")
    print(f"              {bandit_data.get('metrics', {}).get('_totals', {}).get('SEVERITY.MEDIUM', 0)} Medium")
    print(f"              {bandit_data.get('metrics', {}).get('_totals', {}).get('SEVERITY.LOW', 0)} Low")
    
except Exception as e:
    print(f"   Error running Bandit: {e}")

# 2. Manual Exploitation Tests
print("\n2. Running manual exploitation tests...")
BASE_URL = "http://localhost:5000"

tests = [
    ("SQL Injection in login", f"{BASE_URL}/login", "POST", {"username": "admin' OR '1'='1", "password": "anything"}),
    ("Debug endpoint exposure", f"{BASE_URL}/debug/users", "GET", None),
    ("Path traversal attempt", f"{BASE_URL}/download?file=../config.py", "GET", None),
]

for test_name, url, method, data in tests:
    try:
        if method == "POST":
            r = requests.post(url, data=data)
        else:
            r = requests.get(url)
        
        if r.status_code == 200:
            print(f"   ✓ {test_name} - VULNERABLE (200 OK)")
        else:
            print(f"   ✗ {test_name} - Blocked ({r.status_code})")
    except Exception as e:
        print(f"   ✗ {test_name} - Error: {e}")

# 3. Configuration Analysis
print("\n3. Analyzing configuration files...")
config_issues = []

with open('config.py', 'r') as f:
    config = f.read()
    
checks = [
    ("DEBUG = True", "Debug mode enabled in production"),
    ("super_secret_key_12345", "Hardcoded secret key"),
    ("password123", "Hardcoded database password"),
    ("ALLOWED_ORIGINS = ['*']", "Insecure CORS configuration"),
    ("'exe'", "Executable files allowed in uploads"),
]

for pattern, issue in checks:
    if pattern in config:
        config_issues.append(issue)
        print(f"   ✓ {issue}")

print(f"\n✅ Control tests complete. Found {len(config_issues)} config issues.")
