# AI Security Audit Experiment Log
**Researcher:** Jonah  
**Project:** VulnNote - AI vs Traditional Security Tools  
**Status:** Phase 2 Complete ✅ | Phase 3 Pending

---

## EXPERIMENT OVERVIEW

### Goal:
Test GenAI's ability to:
1. Discover security vulnerabilities in AI-generated code
2. Generate secure patches for identified vulnerabilities  
3. Compare AI performance against industry-standard tools (Bandit)

### Methodology:
5-Phase Approach:
1. ✅ Codebase creation & control establishment
2. ✅ AI discovery testing (component analysis)  
3. ⏳ Cross-model comparison
4. ⏳ AI patch generation
5. ⏳ Final analysis & reporting

---

## EXPERIMENT 1: DEEPSEEK ANALYSIS (COMPLETE)

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
- **Strengths:** Excellent at finding SQLi, path traversal, debug exposures
- **Weaknesses:** Missed some logic flaws, didn't analyze imported modules
- **Hallucinations:** Minimal - all findings were valid security issues

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

### Test 1.4: Configuration Module (config.py)
**Model:** DeepSeek Chat  
**File:** config.py (Configuration module)

**Results Summary:**
- **Total Findings:** 7
- **True Positives:** 5/5 (100% recall)
- **False Positives:** 0
- **False Negatives:** 0
- **Precision:** 100%
- **Recall:** 100%

**Expected vs Found:**
| Expected VULN | Found? | AI Finding | Notes |
|---------------|--------|------------|-------|
| VULN-1 (Hardcoded secrets) | ✓ | Finding 1 | Critical - All 3 secrets identified |
| VULN-2 (Debug enabled) | ✓ | Finding 3 | High - Production concern |
| VULN-3 (Weak crypto) | ✓ | Finding 2 | High - DES algorithm |
| VULN-4 (Insecure CORS) | ✓ | Finding 4 | Medium/High - Wildcard CORS |
| VULN-5 (File config) | ✓ | Finding 5 | Medium - .exe allowed, 100MB files |

**Additional Findings:**
1. Missing configuration validation (Medium)
2. Weak database password emphasis (High)

**Performance Score:** 10/10

**Key Observations:**
- Perfect configuration analysis
- Understands production vs development settings
- Provides environment variable best practices
- No hallucinations or false positives

---

### Test 1.5: Frontend Template (templates/index.html)
**Model:** DeepSeek Chat  
**File:** templates/index.html

**Results Summary:**
- **Total Findings:** 12
- **True Positives:** 3/3 (100% recall)
- **False Positives:** 0
- **False Negatives:** 0
- **Precision:** 100%
- **Recall:** 100%

**Expected vs Found:**
| Expected VULN | Found? | AI Finding | Notes |
|---------------|--------|------------|-------|
| VULN-28 (DOM XSS) | ✓ | Finding 1 | Critical - document.write vulnerability |
| VULN-29 (Missing CSRF) | ✓ | Finding 4 | Medium - No CSRF token |
| VULN-30 (External script) | ✓ | Finding 2 | High - Insecure CDN |

**Additional Findings:** 9 (CSP, security headers, encoding, etc.)

**Performance Score:** 10/10

**Key Observations:**
- Excellent XSS analysis
- Comprehensive security headers knowledge
- Modern security practices
- No false positives

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

## DEEPSEEK PERFORMANCE SUMMARY (COMPLETE)

| Component | Expected Vulns | Found | Recall | Precision | Score |
|-----------|---------------|-------|--------|-----------|-------|
| app.py | 13 | 8 | 62% | 53% | 7/10 |
| auth.py | 3 | 3 | 100% | 100% | 10/10 |
| database.py | 4 | 3 | 75% | 100% | 8.5/10 |
| config.py | 5 | 5 | 100% | 100% | 10/10 |
| templates/ | 3 | 3 | 100% | 100% | 10/10 |
| **TOTAL** | **28** | **22** | **78.6%** | **~85%** | **9.2/10** |

**Overall DeepSeek Performance:** 9.2/10

**Strengths:**
- Cryptographic analysis: 10/10 (Perfect)
- SQL injection detection: 9/10 (Excellent)
- Configuration analysis: 10/10 (Perfect)
- XSS/Client-side analysis: 10/10 (Perfect)
- Detailed, actionable fixes

**Weaknesses:**
- Business logic detection: 7/10 (Good, missed some IDOR)
- Requires component analysis for best results

---

## FINAL METRICS CALCULATION

### Discovery Metrics:
- **Overall Recall:** 22/28 = 78.6%
- **Overall Precision:** ~85% (most findings valid)
- **False Positive Rate:** ~15%
- **False Negative Rate:** 21.4%
- **Total Findings:** 50 (22 expected + 28 additional)
- **Components Audited:** 5/5 (100%)

### Comparison vs Control:
| Metric | DeepSeek | Bandit (Control) |
|--------|----------|------------------|
| **Total Findings** | 50 | 18 |
| **Expected Vulns Found** | 22/28 (78.6%) | Pattern-based |
| **Recall Rate** | 78.6% | N/A (pattern-based) |
| **Precision Rate** | ~85% | ~90% |
| **False Positives** | Low | Medium |
| **Additional Findings** | 28 | N/A |
| **Fix Quality** | High (detailed code) | None (only detection) |

**Key Differences:**
- **Overlap:** SQL injection, hardcoded values, cryptographic weaknesses
- **Unique to Bandit:** Subprocess warnings, specific pattern matches
- **Unique to AI:** Business logic, timing attacks, contextual fixes, security headers

---

## KEY INSIGHTS & LESSONS LEARNED

### Effective Strategies:
1. **Component-based analysis** yields better results than full-code analysis
2. **Clear, structured prompts** with specific requirements improve accuracy
3. **Role-based prompts** ("Senior security engineer") yield professional analysis
4. **Explicit output formatting** reduces parsing effort

### AI Limitations Discovered:
1. Can miss subtle business logic flaws (e.g., IDOR)
2. Requires all related files for comprehensive analysis
3. May need multiple prompts for complete coverage
4. Context windows limit analysis scope

### Methodology Improvements:
1. Start with component analysis, then full code
2. Use control tools for baseline comparison
3. Track precision/recall for each component
4. Document prompt effectiveness for reproducibility

### Most Effective Prompts:
1. **Component-focused** with clear module purpose
2. **Structured output requirements** (type, location, severity, description, fix)
3. **Role-based** ("Senior security engineer")
4. **Explicit instructions** to avoid hallucinations

---

## NEXT STEPS

### Phase 3: Cross-Model Comparison
1. Test **ChatGPT** on same codebase (app.py + components)
2. Test **Claude** on same codebase
3. Compare findings across all 3 models
4. Calculate comparative metrics

### Phase 4: AI Patch Generation
1. Select top 5 vulnerabilities for patching
2. Generate patches with each AI model
3. Test patches for correctness
4. Compare patch quality across models

### Phase 5: Final Analysis & Reporting
1. Compile all data into final report
2. Calculate cost/benefit metrics
3. Write conclusions and recommendations
4. Create developer guidelines

---

## FILE REFERENCES

### AI Logs (DeepSeek):
- `ai_logs/deepseek_app_audit.md` - Full app.py results
- `ai_logs/deepseek_auth_audit.md` - auth.py results
- `ai_logs/deepseek_database_audit.md` - database.py results
- `ai_logs/deepseek_config_audit.md` - config.py results
- `ai_logs/deepseek_template_audit.md` - template results

### Control Results:
- `control/bandit_results.json` - Bandit output
- `control/control_test_results.json` - Dynamic tests

### Tracking:
- `findings/master_tracker.csv` - All findings database
- `findings/deepseek_tracker.csv` - DeepSeek-specific findings

---

**Phase 2 Status:** COMPLETE ✅  
**Last Updated:** 2025-12-02  
**Next Phase:** Cross-model comparison (ChatGPT & Claude)
