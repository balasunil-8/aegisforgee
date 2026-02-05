import json

with open(r'c:\vuln_api_testing\vulnshop_newman_report.json', 'r') as f:
    data = json.load(f)

print("=" * 80)
print("POSTMAN COLLECTION RUN SUMMARY (VULNERABLE API)")
print("=" * 80)
print()

# Extract stats
stats = data['run']['stats']
print(f"Test Execution Summary:")
print(f"  Total Requests: {stats['requests']['total']}")
print(f"  Total Tests: {stats['tests']['total']}")
print(f"  Tests Passed: {stats['tests']['total'] - stats['tests']['failed']}")
print(f"  Tests Failed: {stats['tests']['failed']}")
print()

# Extract test results
print("=" * 80)
print("DETAILED TEST RESULTS:")
print("=" * 80)

executions = data['run']['executions']

for exe in executions:
    item_name = exe['item']['name']
    assertions = exe['assertions']
    
    for assertion in assertions:
        test_name = assertion['assertion']
        
        # Determine PASS/FAIL based on test name
        if 'PASS' in test_name:
            status = '✓ PASS (Secure behavior)'
        elif 'FAIL' in test_name:
            status = '✗ FAIL (Vulnerable behavior)'
        elif 'SKIP' in test_name:
            status = '⊘ SKIP'
        else:
            status = '? UNKNOWN'
        
        print(f"{status}: {test_name[:75]}")

print()
print("=" * 80)
