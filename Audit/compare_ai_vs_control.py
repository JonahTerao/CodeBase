import json

print("=== AI vs CONTROL COMPARISON ===\n")

# Load Bandit results
with open('control/bandit_results.json', 'r') as f:
    bandit_data = json.load(f)

bandit_issues = bandit_data.get('results', [])

# DeepSeek findings from earlier (you'll need to enter these)
deepseek_findings = [
    {"type": "SQL Injection", "location": "app.py:21-23", "severity": "Critical"},
    {"type": "IDOR", "location": "app.py:34-45", "severity": "High"},
    {"type": "Path Traversal", "location": "app.py:66-71", "severity": "Critical"},
    {"type": "Information Exposure", "location": "app.py:98-106", "severity": "High"},
    {"type": "Insecure File Upload", "location": "app.py:73-86", "severity": "High"},
    {"type": "Missing HTTPS", "location": "app.py:8-10", "severity": "Medium"},
    {"type": "SQL Injection", "location": "app.py:108-112", "severity": "Medium"},
    {"type": "Weak Token Generation", "location": "app.py:29", "severity": "High"},
    {"type": "Missing Rate Limiting", "location": "app.py:16-31", "severity": "Medium"},
    {"type": "Information Disclosure", "location": "app.py:46-48", "severity": "Medium"},
    {"type": "Missing Input Validation", "location": "app.py:51-60", "severity": "Low"},
    {"type": "Insecure Configuration", "location": "app.py:116", "severity": "Medium"},
    {"type": "XSS Potential", "location": "app.py:115-116", "severity": "Low"},
    {"type": "Insufficient Authorization", "location": "app.py:90-96", "severity": "Low"},
    {"type": "Missing Security Headers", "location": "app.py", "severity": "Low"},
]

print("BANDIT (Control Tool) Findings:")
print(f"  Total: {len(bandit_issues)} issues")
print(f"  High: {sum(1 for i in bandit_issues if i.get('issue_severity') == 'HIGH')}")
print(f"  Medium: {sum(1 for i in bandit_issues if i.get('issue_severity') == 'MEDIUM')}")
print(f"  Low: {sum(1 for i in bandit_issues if i.get('issue_severity') == 'LOW')}")

print("\nDEEPSEEK (AI) Findings:")
print(f"  Total: {len(deepseek_findings)} issues")
print(f"  Critical/High: {sum(1 for f in deepseek_findings if f['severity'] in ['Critical', 'High'])}")
print(f"  Medium: {sum(1 for f in deepseek_findings if f['severity'] == 'Medium')}")
print(f"  Low: {sum(1 for f in deepseek_findings if f['severity'] == 'Low')}")

# Your known 30 vulnerabilities
known_vulns = 30

print(f"\nKNOWN VULNERABILITIES: {known_vulns} (seeded)")

print("\n=== COMPARISON ===")
print("Bandit Strengths:")
print("  - Finds weak cryptographic functions (MD5)")
print("  - Finds hardcoded passwords")
print("  - Finds SQL injection patterns")
print("  - Consistent, repeatable results")

print("\nAI (DeepSeek) Strengths:")
print("  - Understands context and business logic")
print("  - Finds logical flaws (IDOR, auth bypass)")
print("  - Provides detailed explanations and fixes")
print("  - Can analyze multiple files together")

print("\nOverlap: Both found SQL injection and configuration issues")
print("Unique to Bandit: Weak MD5 usage, subprocess warnings")
print("Unique to AI: Business logic flaws, detailed remediation")
