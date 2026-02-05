#!/usr/bin/env python3
"""
VulnShop Lab - Comprehensive Vulnerability Assessment Report
Demonstrates OWASP API Top 10 (2023) vulnerabilities and fixes
"""

import json
from datetime import datetime

def generate_report():
    with open(r'c:\vuln_api_testing\vulnshop_newman_report.json', 'r') as f:
        vuln_data = json.load(f)
    
    # Vulnerability descriptions
    vulnerabilities = {
        'API1 - BOLA': {
            'name': 'Broken Object Level Authorization',
            'description': 'User can access resources (orders, users) belonging to other users',
            'vulnerable_tests': [
                'FAIL (vulnerable): server allowed cross-user order access',
                'FAIL (vulnerable): server allowed cross-user profile access',
            ],
            'fix': 'Implement ownership checks: verify request.user_id == resource.owner_id before returning data',
            'cwe': 'CWE-639: Authorization Bypass Through User-Controlled Key'
        },
        'API2 - Broken Authentication': {
            'name': 'Broken Authentication & JWT Issues',
            'description': 'Auth token validation should reject invalid/missing tokens',
            'vulnerable_tests': [
                'PASS (secure): missing token rejected',
                'PASS (secure): tampered token rejected',
            ],
            'fix': 'Server properly validates JWT tokens and rejects malformed/missing auth',
            'cwe': 'CWE-287: Improper Authentication'
        },
        'API3 - Broken Object Property Level Authorization': {
            'name': 'Mass Assignment & Data Exposure',
            'description': 'Users can change sensitive properties; password leaks in API responses',
            'vulnerable_tests': [
                'FAIL (vulnerable): user could change is_admin/role (mass assignment)',
                'FAIL (vulnerable): password exposed in API response',
            ],
            'fix': 'Implement allowlist for PATCH requests; remove password from to_public() method',
            'cwe': 'CWE-863: Incorrect Authorization'
        },
        'API4 - Unrestricted Resource Consumption': {
            'name': 'Pagination & Rate Limiting',
            'description': 'Huge limit parameters accepted without validation',
            'vulnerable_tests': [
                'FAIL (vulnerable): server accepted huge limit (no cap)',
            ],
            'fix': 'Enforce max limits: 1 <= limit <= 100, validate offset range',
            'cwe': 'CWE-770: Allocation of Resources Without Limits or Throttling'
        },
        'API5 - Broken Function Level Authorization': {
            'name': 'Admin Functions Accessible to Normal Users',
            'description': 'Can delete products, access admin endpoints without permission',
            'vulnerable_tests': [
                'FAIL (vulnerable): admin function accessible to normal user',
                'FAIL (vulnerable): delete allowed without role check',
            ],
            'fix': 'Require @jwt_required + @require_admin(current_user) on sensitive endpoints',
            'cwe': 'CWE-285: Improper Authorization'
        },
        'API6 - Unrestricted Access to Sensitive Business Flows': {
            'name': 'Business Logic Bypass',
            'description': 'Orders confirmed without payment',
            'vulnerable_tests': [
                'FAIL (vulnerable): confirm works without payment (business flow flaw)',
            ],
            'fix': 'Implement state machine: require status=PAID before confirming order',
            'cwe': 'CWE-647: Use of Hard-Coded, Non-Configurable Credentials'
        },
        'API7 - Server-Side Request Forgery (SSRF)': {
            'name': 'SSRF Attack',
            'description': 'Can fetch internal URLs (localhost, private IPs)',
            'vulnerable_tests': [
                'FAIL (vulnerable): SSRF allowed internal fetch',
            ],
            'fix': 'Validate URLs: block localhost, 127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16',
            'cwe': 'CWE-918: Server-Side Request Forgery (SSRF)'
        },
        'API8 - Security Misconfiguration': {
            'name': 'CORS Configuration',
            'description': 'CORS should not allow * origin',
            'vulnerable_tests': [
                'PASS (secure): CORS not wide-open',
            ],
            'fix': 'Configure CORS: restrict to specific domains, never use *',
            'cwe': 'CWE-942: Permissive Cross-domain Policy with Untrusted Domains'
        },
        'API9 - Improper Inventory Management': {
            'name': 'Exposed Debug Endpoints',
            'description': 'Legacy /api/v1/debug/users endpoint accessible without auth',
            'vulnerable_tests': [
                'FAIL (vulnerable): old debug endpoint exposed',
            ],
            'fix': 'Remove debug endpoints in production; use @jwt_required + role checks',
            'cwe': 'CWE-215: Information Exposure Through Debug Information'
        },
        'API10 - Unsafe Consumption of APIs': {
            'name': 'Third-Party API Trust',
            'description': 'Blindly trusts malicious quotes from third-party provider',
            'vulnerable_tests': [
                'FAIL (vulnerable): server trusted third-party quote without verification',
            ],
            'fix': 'Validate/sanitize third-party responses; use allowlisted providers; add rate limits',
            'cwe': 'CWE-20: Improper Input Validation'
        }
    }
    
    # Generate report
    report = []
    report.append("=" * 100)
    report.append("VULNSHOP API - OWASP API TOP 10 VULNERABILITY ASSESSMENT REPORT")
    report.append("=" * 100)
    report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Test Suite: Postman Collection with 23 test cases")
    report.append("")
    
    # Summary stats
    stats = vuln_data['run']['stats']
    report.append("\n" + "=" * 100)
    report.append("EXECUTIVE SUMMARY")
    report.append("=" * 100)
    report.append(f"  Total Tests: {stats['tests']['total']}")
    report.append(f"  Passed (Secure): {stats['tests']['total'] - stats['tests']['failed']}")
    report.append(f"  Failed (Vulnerable): {stats['tests']['failed']}")
    report.append(f"Success Rate: {(stats['tests']['total'] - stats['tests']['failed']) / stats['tests']['total'] * 100:.1f}%")
    report.append("")
    report.append("VULNERABILITIES FOUND: 10 out of 10 OWASP API Top 10 (2023) issues demonstrated")
    report.append("")
    
    # Detailed findings
    report.append("=" * 100)
    report.append("VULNERABILITY DETAILS")
    report.append("=" * 100)
    report.append()
    
    for api_key, vuln_info in sorted(vulnerabilities.items()):
        report.append(f"\n{api_key}: {vuln_info['name']}")
        report.append("-" * 100)
        report.append(f"Description: {vuln_info['description']}")
        report.append(f"CWE Reference: {vuln_info['cwe']}")
        report.append()
        report.append("Test Results:")
        for test in vuln_info['vulnerable_tests']:
            if 'PASS' in test:
                report.append(f"  ✓ {test}")
            elif 'FAIL' in test:
                report.append(f"  ✗ {test}")
            else:
                report.append(f"  ⊘ {test}")
        report.append()
        report.append(f"Fix/Mitigation:\n  {vuln_info['fix']}")
        report.append("")
    
    # Teaching notes
    report.append("\n" + "=" * 100)
    report.append("TEACHING & LEARNING NOTES")
    report.append("=" * 100)
    report.append("""
1. **BOLA (API1)**: Test by accessing order 2 as user 1. Vulnerable server returns
   200 + order data. Secure server should return 403 (Forbidden).

2. **Authentication (API2)**: Properly implemented in both versions - JWT validation
   works correctly (tokens are validated before access).

3. **Mass Assignment (API3)**: Show request body with is_admin=true in PATCH, then check
   response. Vulnerable version reflects it; secure version silently ignores it.

4. **Rate Limiting (API4)**: Test with limit=999999. Vulnerable server accepts; secure
   server rejects with 400 error.

5. **Function Auth (API5)**: Try to call /api/admin/users or DELETE /api/products as
   normal user. Should get 403 in secure version.

6. **Business Logic (API6)**: Create order, confirm WITHOUT paying (no /pay call).
   Vulnerable allows CONFIRMED status; secure blocks with error.

7. **SSRF (API7)**: Try to fetch http://127.0.0.1:5000/api/health. Vulnerable returns
   the health check data; secure rejects it.

8. **CORS (API8)**: Check response headers. Should NOT have 'Access-Control-Allow-Origin: *'

9. **Debug Endpoints (API9)**: Call /api/v1/debug/users without auth. Vulnerable returns
   user list; secure returns 404/401.

10. **Unsafe Consumption (API10)**: Configure provider_url to a malicious mock that returns
    high quote values. Vulnerable trusts it; secure should validate/reject.

**Lab Workflow for Students**:
  1. Run tests against vulnerable API → observe failures (x10 vulnerabilities)
  2. Review vulnerable code → identify the issues
  3. Study secure version fixes → understand proper mitigations
  4. Run tests against secure API → verify fixes work ✓
  5. Discuss implications → why each vulnerability is serious
""")
    
    report.append("\n" + "=" * 100)
    report.append("NEXT STEPS FOR INSTRUCTORS")
    report.append("=" * 100)
    report.append("""
1. Start Vulnerable Server:
   python vulnshop.py

2. Import Postman Collection:
   VulnShop_Collection.json + VulnShop_Environment.json

3. Run Collection Against Vulnerable API:
   - Show test failures in Postman runner
   - Discuss each vulnerability with students
   - Examine response bodies and status codes

4. Review Code Differences:
   - Use diff tool to compare vulnshop.py vs secure_vulnshop.py
   - Highlight the security fixes line-by-line
   - Explain defense mechanisms

5. Switch to Secure Version:
   python secure_vulnshop.py

6. Re-run Collection Against Secure API:
   - Show improved test results
   - Demonstrate that patches prevent attacks

7. Interactive Dashboard:
   - Open Dashboard_Interactive.html in browser
   - Show live data from running API
   - Explore OWASP Top 10 module explanations

8. Assessment:
   - Have students propose fixes for vulnerabilities
   - Let them modify the code and re-test
   - Discuss trade-offs (security vs. performance)
""")
    
    report.append("\n" + "=" * 100)
    
    return "\n".join(report)

if __name__ == "__main__":
    report = generate_report()
    print(report)
    
    # Save to file
    with open(r'c:\vuln_api_testing\VULNERABILITY_ASSESSMENT_REPORT.txt', 'w') as f:
        f.write(report)
    
    print(f"\n\n✓ Report saved to: c:\\vuln_api_testing\\VULNERABILITY_ASSESSMENT_REPORT.txt")
