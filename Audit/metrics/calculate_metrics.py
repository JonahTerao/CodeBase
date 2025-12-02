import csv

print("=== AI Audit Metrics Calculator ===\n")

# Load findings
findings = []
with open('findings/master_tracker.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        findings.append(row)

# Calculate metrics
total_findings = len(findings)
true_positives = sum(1 for f in findings if f['True_Positive'] == 'TRUE')
false_positives = sum(1 for f in findings if f['False_Positive'] == 'TRUE')
valid_findings = sum(1 for f in findings if f['Is_Valid'] == 'TRUE')

# Our known vulnerabilities in app.py (13 vulnerabilities)
known_app_vulns = 13
found_app_vulns = true_positives  # These match our VULN-XX

print(f"DeepSeek Performance Analysis:\n")
print(f"Total findings reported: {total_findings}")
print(f"Valid findings (TP + FP): {valid_findings}")
print(f"True Positives (matched our vulns): {true_positives}")
print(f"False Positives (new valid issues): {false_positives}")
print(f"Invalid findings: {total_findings - valid_findings}")

print(f"\nPrecision (TP / Total Reported): {true_positives}/{total_findings} = {(true_positives/total_findings)*100:.1f}%")
print(f"Recall for app.py (Found / Known): {found_app_vulns}/{known_app_vulns} = {(found_app_vulns/known_app_vulns)*100:.1f}%")

# Breakdown by severity
severities = {}
for f in findings:
    sev = f['Severity']
    severities[sev] = severities.get(sev, 0) + 1

print(f"\nSeverity Breakdown:")
for sev, count in severities.items():
    print(f"  {sev}: {count}")

print(f"\n✅ DeepSeek found {true_positives} of {known_app_vulns} vulnerabilities in app.py")
print(f"📝 Also identified {false_positives} additional security issues")
