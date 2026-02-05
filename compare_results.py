import json

print("=" * 100)
print("COMPARISON: VULNERABLE vs SECURE API")
print("=" * 100)
print()

# Load both reports
with open(r'c:\vuln_api_testing\vulnshop_newman_report.json', 'r') as f:
    vuln_data = json.load(f)

with open(r'c:\vuln_api_testing\vulnshop_secure_report.json', 'r') as f:
    secure_data = json.load(f)

# Extract stats
vuln_stats = vuln_data['run']['stats']
secure_stats = secure_data['run']['stats']

print("STATISTICS")
print("-" * 100)
print(f"{'Metric':<40} {'Vulnerable':<25} {'Secure':<25}")
print("-" * 100)
print(f"{'Total Tests':<40} {vuln_stats['tests']['total']:<25} {secure_stats['tests']['total']:<25}")
print(f"{'Tests Passed':<40} {vuln_stats['tests']['total'] - vuln_stats['tests']['failed']:<25} {secure_stats['tests']['total'] - secure_stats['tests']['failed']:<25}")
print(f"{'Tests Failed':<40} {vuln_stats['tests']['failed']:<25} {secure_stats['tests']['failed']:<25}")
print()

# Extract detailed results
print("=" * 100)
print("DETAILED RESULTS (Test-by-Test Comparison)")
print("=" * 100)

vuln_exes = vuln_data['run']['executions']
secure_exes = secure_data['run']['executions']

# Create dicts keyed by test name
vuln_results = {}
secure_results = {}

for exe in vuln_exes:
    for assertion in exe['assertions']:
        test_name = assertion['assertion']
        vuln_results[test_name] = test_name

for exe in secure_exes:
    for assertion in exe['assertions']:
        test_name = assertion['assertion']
        secure_results[test_name] = test_name

# Get all unique test names
all_tests = set(vuln_results.keys()) | set(secure_results.keys())

print(f"{'Status':<8} {'Test Name':<75}")
print("-" * 100)

for test_name in sorted(all_tests):
    vuln_has = test_name in vuln_results
    secure_has = test_name in secure_results
    
    if 'PASS' in test_name:
        icon = '✓'
    elif 'FAIL' in test_name:
        icon = '✗'
    elif 'SKIP' in test_name:
        icon = '⊘'
    else:
        icon = '○'
    
    # Show change
    if vuln_has and secure_has:
        if 'FAIL (vulnerable)' in test_name and 'FAIL (vulnerable)' in test_name:
            change = "→ (still vulnerable in secure)"
        else:
            change = ""
        status = f"{icon} {change}" if change else icon
    else:
        status = icon
    
    print(f"{status:<8} {test_name:<75}")

print()
print("=" * 100)
print("LEGEND:")
print("  ✓ = PASS (security check passed / secure behavior)")
print("  ✗ = FAIL (vulnerability detected / insecure behavior)")
print("  ⊘ = SKIP (test skipped)")
print("  ○ = (setup/utility test)")
print("=" * 100)
