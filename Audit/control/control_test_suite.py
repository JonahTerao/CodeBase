import os
import json
import requests
import subprocess
import sqlite3
from datetime import datetime

class ControlTester:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.results = []
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
    def run_all_tests(self):
        print(f"=== CONTROL TEST SUITE === {self.timestamp}\n")
        
        # 1. Static Analysis with Bandit
        self.run_static_analysis()
        
        # 2. Dynamic/Manual Tests
        self.run_dynamic_tests()
        
        # 3. Database Inspection
        self.check_database()
        
        # 4. Configuration Audit
        self.audit_configuration()
        
        # 5. Generate Report
        self.generate_report()
    
    def run_static_analysis(self):
        print("1. STATIC ANALYSIS (Bandit)")
        print("-" * 40)
        
        try:
            # Run bandit
            cmd = ['bandit', '-r', '.', '-f', 'json', '--quiet']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                
                # Categorize findings
                categories = {
                    "SQL": ["sql", "injection"],
                    "XSS": ["xss", "cross-site"],
                    "Secrets": ["hardcoded", "password", "secret"],
                    "File Operations": ["path", "traversal", "insecure"],
                    "General": []
                }
                
                for finding in data.get('results', []):
                    issue_type = finding.get('issue_text', '').lower()
                    matched = False
                    
                    for cat, keywords in categories.items():
                        if any(kw in issue_type for kw in keywords):
                            self.record_finding(
                                source="Bandit",
                                category=cat,
                                location=finding.get('filename'),
                                description=finding.get('issue_text'),
                                severity=finding.get('issue_severity', 'MEDIUM'),
                                test_result="FOUND"
                            )
                            matched = True
                            break
                    
                    if not matched:
                        self.record_finding(
                            source="Bandit",
                            category="General",
                            location=finding.get('filename'),
                            description=finding.get('issue_text'),
                            severity=finding.get('issue_severity', 'MEDIUM'),
                            test_result="FOUND"
                        )
                
                print(f"   Bandit found {len(data.get('results', []))} issues")
            else:
                print("   Bandit failed to run")
                
        except Exception as e:
            print(f"   Error: {e}")
    
    def run_dynamic_tests(self):
        print("\n2. DYNAMIC TESTS (Manual Exploitation)")
        print("-" * 40)
        
        tests = [
            self.test_sql_injection_login,
            self.test_path_traversal,
            self.test_debug_endpoint,
            self.test_idor,
            self.test_xss,
        ]
        
        for test_func in tests:
            test_func()
    
    def test_sql_injection_login(self):
        """Test SQL injection in login"""
        payloads = [
            ("admin' OR '1'='1", "anything"),
            ("admin' --", "anything"),
            ("' OR '1'='1' --", "anything"),
        ]
        
        vulnerable = False
        for username, password in payloads:
            try:
                r = requests.post(
                    f"{self.base_url}/login",
                    data={"username": username, "password": password},
                    timeout=5
                )
                if r.status_code == 200 and "user_id" in r.text:
                    vulnerable = True
                    break
            except:
                continue
        
        self.record_finding(
            source="Dynamic",
            category="SQL Injection",
            location="app.py:login()",
            description="SQL Injection in login endpoint",
            severity="CRITICAL",
            test_result="VULNERABLE" if vulnerable else "SAFE"
        )
        
        print(f"   SQL Injection in login: {'VULNERABLE' if vulnerable else 'SAFE'}")
    
    def test_path_traversal(self):
        """Test path traversal in download"""
        try:
            # First create a test file
            os.makedirs("uploads", exist_ok=True)
            with open("uploads/test.txt", "w") as f:
                f.write("test")
            
            # Test traversal
            r = requests.get(f"{self.base_url}/download?file=../config.py", timeout=5)
            
            vulnerable = r.status_code == 200 and "SECRET_KEY" in r.text
            
            self.record_finding(
                source="Dynamic",
                category="Path Traversal",
                location="app.py:download_file()",
                description="Path traversal in file download",
                severity="CRITICAL",
                test_result="VULNERABLE" if vulnerable else "SAFE"
            )
            
            print(f"   Path traversal: {'VULNERABLE' if vulnerable else 'SAFE'}")
            
        except Exception as e:
            print(f"   Path traversal test error: {e}")
    
    def test_debug_endpoint(self):
        """Test debug endpoint exposure"""
        try:
            r = requests.get(f"{self.base_url}/debug/users", timeout=5)
            
            vulnerable = r.status_code == 200 and "users" in r.text
            
            self.record_finding(
                source="Dynamic",
                category="Information Disclosure",
                location="app.py:debug_users()",
                description="Debug endpoint exposes sensitive data",
                severity="HIGH",
                test_result="VULNERABLE" if vulnerable else "SAFE"
            )
            
            print(f"   Debug endpoint: {'VULNERABLE' if vulnerable else 'SAFE'}")
            
        except Exception as e:
            print(f"   Debug endpoint test error: {e}")
    
    def test_idor(self):
        """Test Insecure Direct Object References"""
        # This requires a logged-in session
        print("   IDOR test: Requires authenticated session (manual testing needed)")
        
        self.record_finding(
            source="Dynamic",
            category="IDOR",
            location="app.py:get_note(), database.py:get_note_by_id()",
            description="Missing ownership check on note access",
            severity="HIGH",
            test_result="MANUAL_TEST_NEEDED"
        )
    
    def test_xss(self):
        """Test for XSS vulnerabilities"""
        print("   XSS test: Manual testing via browser needed")
        
        self.record_finding(
            source="Dynamic",
            category="XSS",
            location="app.py:index(), templates/index.html",
            description="Potential XSS in search parameter",
            severity="MEDIUM",
            test_result="MANUAL_TEST_NEEDED"
        )
    
    def check_database(self):
        print("\n3. DATABASE INSPECTION")
        print("-" * 40)
        
        try:
            conn = sqlite3.connect('vulnnote.db')
            cursor = conn.cursor()
            
            # Check for default credentials
            cursor.execute("SELECT username, password FROM users WHERE username='admin'")
            admin = cursor.fetchone()
            
            if admin and admin[1] == '0192023a7bbd73250516f069df18b500':  # MD5 of admin123
                self.record_finding(
                    source="Database",
                    category="Default Credentials",
                    location="database.py:init_db()",
                    description="Default admin credentials (admin/admin123)",
                    severity="HIGH",
                    test_result="FOUND"
                )
                print("   Default admin credentials: FOUND")
            
            # Check if passwords are plaintext (they shouldn't be after your fix)
            cursor.execute("SELECT password FROM users LIMIT 1")
            sample = cursor.fetchone()
            if sample:
                is_md5 = len(sample[0]) == 32 and all(c in '0123456789abcdef' for c in sample[0])
                self.record_finding(
                    source="Database",
                    category="Password Storage",
                    location="auth.py:hash_password()",
                    description="Password hashing implementation",
                    severity="MEDIUM" if is_md5 else "CRITICAL",
                    test_result="MD5_HASH" if is_md5 else "PLAINTEXT"
                )
                print(f"   Password storage: {'MD5 (weak)' if is_md5 else 'PLAINTEXT (CRITICAL)'}")
            
            conn.close()
            
        except Exception as e:
            print(f"   Database check error: {e}")
    
    def audit_configuration(self):
        print("\n4. CONFIGURATION AUDIT")
        print("-" * 40)
        
        config_checks = [
            ("config.py", "DEBUG = True", "Debug mode in production", "HIGH"),
            ("config.py", "super_secret_key_12345", "Hardcoded secret key", "HIGH"),
            ("config.py", "ALLOWED_ORIGINS = ['*']", "Insecure CORS", "MEDIUM"),
            ("config.py", "'exe'", "Executable files allowed", "HIGH"),
            ("config.py", "CRYPTO_ALGO = 'DES'", "Weak crypto algorithm", "HIGH"),
            ("app.py", "host='0.0.0.0'", "Binding to all interfaces", "MEDIUM"),
        ]
        
        for file, pattern, description, severity in config_checks:
            try:
                with open(file, 'r') as f:
                    content = f.read()
                
                if pattern in content:
                    self.record_finding(
                        source="Configuration",
                        category="Misconfiguration",
                        location=file,
                        description=description,
                        severity=severity,
                        test_result="FOUND"
                    )
                    print(f"   {description}: FOUND")
            except:
                pass
    
    def record_finding(self, source, category, location, description, severity, test_result):
        self.results.append({
            "source": source,
            "category": category,
            "location": location,
            "description": description,
            "severity": severity,
            "test_result": test_result,
            "timestamp": self.timestamp
        })
    
    def generate_report(self):
        print("\n5. GENERATING REPORT")
        print("-" * 40)
        
        # Count by severity
        severities = {}
        categories = {}
        
        for finding in self.results:
            sev = finding["severity"]
            cat = finding["category"]
            
            severities[sev] = severities.get(sev, 0) + 1
            categories[cat] = categories.get(cat, 0) + 1
        
        print("\n=== SUMMARY ===")
        print(f"Total findings: {len(self.results)}")
        
        print("\nBy Severity:")
        for sev, count in sorted(severities.items()):
            print(f"  {sev}: {count}")
        
        print("\nBy Category:")
        for cat, count in sorted(categories.items()):
            print(f"  {cat}: {count}")
        
        # Save to file
        report = {
            "timestamp": self.timestamp,
            "summary": {
                "total_findings": len(self.results),
                "by_severity": severities,
                "by_category": categories
            },
            "findings": self.results
        }
        
        os.makedirs("control", exist_ok=True)
        with open("control/control_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        # Also create CSV for easy comparison
        import csv
        with open("control/control_findings.csv", "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
            writer.writeheader()
            writer.writerows(self.results)
        
        print(f"\n✅ Reports saved to:")
        print(f"   control/control_report.json")
        print(f"   control/control_findings.csv")

if __name__ == "__main__":
    # Make sure Flask is running first!
    print("IMPORTANT: Ensure Flask app is running on http://localhost:5000")
    print("Run in another terminal: python app.py")
    input("Press Enter when ready...")
    
    tester = ControlTester()
    tester.run_all_tests()
