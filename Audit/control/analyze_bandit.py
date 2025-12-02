import json
import os

print("=== BANDIT RESULTS ANALYSIS ===\n")

# Load Bandit results
try:
    with open('control/bandit_results.json', 'r') as f:
        data = json.load(f)
    
    print(f"Bandit found {len(data.get('results', []))} security issues:\n")
    
    # Group by severity
    severities = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
    
    for issue in data.get('results', []):
        severity = issue.get('issue_severity', 'MEDIUM')
        text = issue.get('issue_text', 'Unknown')
        file = issue.get('filename', 'Unknown')
        line = issue.get('line_number', '?')
        
        if severity in severities:
            severities[severity].append(f"{file}:{line} - {text}")
    
    # Print by severity
    for severity in ['HIGH', 'MEDIUM', 'LOW']:
        issues = severities[severity]
        if issues:
            print(f"{severity} Severity ({len(issues)}):")
            for i, issue in enumerate(issues[:5], 1):
                print(f"  {i}. {issue}")
            if len(issues) > 5:
                print(f"  ... and {len(issues)-5} more")
            print()
    
    # Show metrics
    metrics = data.get('metrics', {}).get('_totals', {})
    print("\n=== METRICS ===")
    print(f"Confidence High: {metrics.get('CONFIDENCE.HIGH', 0)}")
    print(f"Confidence Medium: {metrics.get('CONFIDENCE.MEDIUM', 0)}")
    print(f"Confidence Low: {metrics.get('CONFIDENCE.LOW', 0)}")
    
except FileNotFoundError:
    print("Error: bandit_results.json not found")
    print("Run: python -m bandit -r . -f json -o control/bandit_results.json")
except Exception as e:
    print(f"Error: {e}")
