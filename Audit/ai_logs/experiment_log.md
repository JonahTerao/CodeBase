# AI Security Audit Experiment Log
**Researcher:** Jonah
---
## EXPERIMENT OVERVIEW

### Goal:
Test GenAI's ability to:
1. Discover security vulnerabilities in AI-generated code
2. Generate secure patches for identified vulnerabilities
3. Compare AI performance against industry-standard tools (Bandit)

### Methodology:
5-Phase Approach:
1. Codebase creation & control establishment
2. AI discovery testing (component analysis)
3. Cross-model comparison
4. AI patch generation
5. Final analysis & reporting

---

## EXPERIMENT 1: DEEPSEEK ANALYSIS

### Test 1.1: Full Application Audit (app.py)
**Model:** DeepSeek Chat
**Code:** app.py (cleaned, 116 lines)

**Results Summary:**
- **Total Findings:** 15
- **True Positives:** 8 (matches our seeded vulnerabilities)
- **False Positives:** 7 (valid security issues not in seed list)
- **False Negatives:** 5 (missed vulns from app.py list)
- **Precision:** 53% (8/15)
- **Recall (app.py):** 62% (8/13)

**Detailed Findings:**
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

**Key Observations:**
- Strengths: Excellent at finding SQLi, path traversal, debug exposures
- Weaknesses: Missed some logic flaws, didn't analyze imported modules
- Hallucinations: Minimal - all findings were valid security issues

**Lessons Learned:**
- AI needs all related files to find all vulnerabilities
- Component analysis required for comprehensive audit
- Good at pattern recognition (SQLi, XSS, path traversal)

---

### Test 1.2: Authentication Module (auth.py)
**Model:** DeepSeek Chat
**File:** auth.py (Authentication module)

**Results Summary:**
- **Total Findings:** 7
- **True Positives:** 3/3 (100% recall)
- **False Positives:** 0
- **False Negatives:** 0
- **Precision:** 100%
- **Recall:** 100%

**Expected vs Found:**
| Expected VULN | Found? | AI Finding | Notes |
|---------------|--------|------------|-------|
| VULN-10 (Weak MD5) | ✓ | Finding 1 | Correctly identified as Critical |
| VULN-13 (Timing attack) | ✓ | Finding 2 | Correctly identified as Critical |
| VULN-14 (Weak tokens) | ✓ | Finding 3 | Correctly identified as High |

**Additional Findings:**
1. Finding 4: Lack of input validation (High) - Valid
2. Finding 5: Import inside function (Medium) - Valid code quality issue
3. Finding 6: Information disclosure (Medium) - Valid
4. Finding 7: Missing logging (Low) - Valid

**Performance Score:** 10/10

**Key Observations:**
- Excellent at cryptographic analysis
- Detailed fixes provided
- Understands timing attacks
- No hallucinations
- High-quality, production-ready fixes

---

### Test 1.3: Database Module (database.py)
**Model:** DeepSeek Chat
**File:** database.py (Database module)

**Results Summary:**
- **Total Findings:** 9
- **True Positives:** 3/4 (75% recall)
- **False Positives:** 0
- **False Negatives:** 1 (VULN-9: IDOR missed)
- **Precision:** 100%
- **Recall:** 75%

**Expected vs Found:**
| Expected VULN | Found? | AI Finding | Notes |
|---------------|--------|------------|-------|
| VULN-6 (Hardcoded creds) | ✓ | Finding 2 | Critical - Hardcoded credentials |
| VULN-7 (SQL Injection) | ✓ | Finding 1 | Critical - SQL Injection |
| VULN-8 (Info disclosure) | ✓ | Finding 7 | Medium - Debug logging |
| VULN-9 (IDOR) | ✗ | - | MISSED - No ownership check |

**Additional Findings:**
1. Password storage as plain text (High)
2. Database file location exposure (High)
3. Silent failure handling (Medium)
4. Missing input validation (Medium)
5. Connection management issues (Low)
6. Missing DB security settings (Low)

**Performance Score:** 8.5/10

**Key Observations:**
- Excellent SQL injection detection
- Good credential management analysis
- Missed business logic flaw (IDOR)
- No false positives
- High-quality SQL fixes provided

---

## CONTROL TESTING RESULTS

### Bandit Static Analysis
**Tool:** Bandit v1.9.2

**Results:**
- **Total Findings:** 18
- **High Severity:** 3
- **Medium Severity:** 5
- **Low Severity:** 10

**Key Findings:**
1. Weak MD5 cryptographic functions (3 instances)
2. SQL injection patterns detected
3. Hardcoded passwords
4. Binding to all interfaces
5. Subprocess usage warnings

**Comparison Insights:**
- **Bandit excels at:** Pattern detection, cryptographic weaknesses, hardcoded values
- **AI excels at:** Business logic, context understanding, detailed remediation
- **Combined approach:** Most comprehensive coverage

---

## DEEPSEEK PERFORMANCE SUMMARY

| Component | Expected Vulns | Found | Recall | Precision | Score |
|-----------|---------------|-------|--------|-----------|-------|
| app.py | 13 | 8 | 62% | 53% | 7/10 |
| auth.py | 3 | 3 | 100% | 100% | 10/10 |
| database.py | 4 | 3 | 75% | 100% | 8.5/10 |
| **Total** | **20** | **14** | **70%** | **~84%** | **8.5/10** |

**Overall DeepSeek Performance:** 8.5/10
- **Strengths:** Cryptographic analysis, SQL injection detection, detailed fixes
- **Weaknesses:** Misses some business logic, requires component analysis
- **Best at:** Pattern-based vulnerabilities with clear indicators
- **Improvement:** Better prompts for business logic analysis

---

## METRICS CALCULATION

### Discovery Metrics:
- **Overall Recall:** 14/20 = 70% (components analyzed so far)
- **Overall Precision:** ~84% (most findings valid)
- **False Positive Rate:** ~16%
- **False Negative Rate:** 30%

### Comparison vs Control:
- **Bandit:** 18 findings (pattern-based)
- **DeepSeek:** 31+ findings (14 expected + 17+ additional)
- **Overlap:** SQL injection, hardcoded values, cryptographic weaknesses
- **Unique to Bandit:** Subprocess warnings, specific pattern matches
- **Unique to AI:** Business logic, timing attacks, contextual fixes

---

