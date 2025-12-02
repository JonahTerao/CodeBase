# Experiment 1: DeepSeek Full app.py Audit
**Model**: DeepSeek Chat
**Code Provided**: app.py (cleaned, 116 lines)

## Results Summary:
- **Total Findings**: 15
- **True Positives**: 8 (matches our seeded vulnerabilities)
- **False Positives**: 7 (valid security issues not in our seed list)
- **False Negatives**: 5 (missed vulns from our app.py list)
- **Precision**: 53% (8/15)
- **Recall (app.py)**: 62% (8/13)

## Key Observations:
1. **Strengths**: Excellent at finding SQLi, path traversal, debug exposures
2. **Weaknesses**: Missed some logic flaws, didn't analyze imported modules
3. **Hallucinations**: Minimal - all findings were valid security issues

## Detailed Findings Matrix:
| Our VULN-ID | Found? | DeepSeek Finding | Notes |
|-------------|--------|------------------|-------|
| VULN-16 | ✓ | Finding 1 | SQLi in login |
| VULN-21 | ✓ | Finding 3 | Path traversal |
| VULN-24 | ✓ | Finding 4 | Debug endpoint |
| VULN-25 | ✓ | Finding 7 | Search SQLi |
| VULN-14 | ✓ | Finding 9 | Weak tokens |
| VULN-15 | ✓ | Finding 10 | No rate limiting |
| VULN-19 | ✓ | Finding 11 | Verbose errors |
| VULN-2,27 | ✓ | Finding 13 | Debug config |
| VULN-9 | ✓ | Finding 2 | IDOR |
| VULN-26 | ✓ | Finding 8 | XSS potential |

## Lessons Learned:
- AI needs all related files to find all vulnerabilities
- Component analysis required for comprehensive audit
- Good at pattern recognition (SQLi, XSS, path traversal)


# Experiment 2: DeepSeek Full Auth.py Audit
Findings Summary:
Total issues found: 7

True Positives (matches our VULN-XX): 3/3 (100%)

False Positives: 0 (all findings are valid security issues)

False Negatives: 0 (found all expected vulnerabilities)

Additional findings: 4 (beyond our seeded vulnerabilities)

Expected vs Found:
Expected VULN	Found?	AI Finding	Notes
VULN-10 (Weak MD5)	✓	Finding 1	Correctly identified as Critical
VULN-13 (Timing attack)	✓	Finding 2	Correctly identified as Critical
VULN-14 (Weak tokens)	✓	Finding 3	Correctly identified as High
Additional Findings:
Finding 4: Lack of input validation (High) - Valid

Finding 5: Import inside function (Medium) - Valid code quality issue

Finding 6: Information disclosure (Medium) - Valid

Finding 7: Missing logging (Low) - Valid

Key Observations:
Strengths: Excellent at cryptographic analysis, detailed fixes provided, understands timing attacks

Weaknesses: None observed for this module

Hallucinations: None - all findings are accurate

Fix Quality: High - provides complete, production-ready code

Severity Assessment: Accurate - correctly prioritized cryptographic issues as Critical

DeepSeek Performance Score: 10/10
Found all seeded vulnerabilities (100% recall)

No false positives (100% precision)

Provided detailed, correct fixes

Additional findings were valid security concerns
