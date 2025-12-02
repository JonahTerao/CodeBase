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
