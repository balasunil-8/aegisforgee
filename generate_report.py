#!/usr/bin/env python
"""
VulnShop API - Test Report Generator
Generates comprehensive reports showing OWASP API Top 10 alignment and test coverage
"""

import json
import sys
from datetime import datetime
from collections import defaultdict

# OWASP API Top 10 Vulnerability Definitions
VULNERABILITIES = {
    "API1": {
        "name": "BOLA (Broken Object Level Authorization)",
        "description": "Attackers can access resources of other users by manipulating object IDs",
        "endpoints": ["/api/users/<id>", "/api/orders/<id>"],
        "vulnerable": True,
        "fix": "Add ownership checks before returning objects"
    },
    "API2": {
        "name": "Broken Authentication",
        "description": "Weak passwords, no rate limiting, insecure token storage",
        "endpoints": ["/api/auth/login"],
        "vulnerable": True,
        "fix": "Hash passwords, implement rate limiting, use secure secrets"
    },
    "API3": {
        "name": "Broken Object Property-Level Authorization",
        "description": "Mass assignment: blindly updates fields; Excessive data exposure: returns sensitive data",
        "endpoints": ["PATCH /api/users/<id>", "GET /api/users/<id>"],
        "vulnerable": True,
        "fix": "Allowlist safe fields, exclude sensitive fields from responses"
    },
    "API4": {
        "name": "Unrestricted Resource Consumption",
        "description": "No pagination limits; attacker can request millions of records",
        "endpoints": ["GET /api/products?limit=999999"],
        "vulnerable": True,
        "fix": "Enforce pagination caps (max 100), rate limiting"
    },
    "API5": {
        "name": "Broken Function-Level Authorization",
        "description": "No role checks; normal users can access admin functions",
        "endpoints": ["DELETE /api/products/<id>", "GET /api/admin/users"],
        "vulnerable": True,
        "fix": "Add role-based access control (RBAC) checks"
    },
    "API6": {
        "name": "Unrestricted Access to Sensitive Business Flows",
        "description": "Business logic not enforced; can confirm orders without paying",
        "endpoints": ["POST /api/orders/<id>/confirm"],
        "vulnerable": True,
        "fix": "Enforce business flow state machines"
    },
    "API7": {
        "name": "SSRF (Server-Side Request Forgery)",
        "description": "API fetches internal URLs; attacker can probe internal network",
        "endpoints": ["POST /api/utils/fetch-url"],
        "vulnerable": True,
        "fix": "Block private IPs, loopback, metadata services"
    },
    "API8": {
        "name": "Security Misconfiguration",
        "description": "Debug mode on, CORS wide open, weak defaults",
        "endpoints": ["Global configuration"],
        "vulnerable": True,
        "fix": "Disable debug, restrict CORS, use strong secrets"
    },
    "API9": {
        "name": "Improper Inventory Management",
        "description": "Old debug endpoints exposed without authentication",
        "endpoints": ["GET /api/v1/debug/users"],
        "vulnerable": True,
        "fix": "Disable old endpoints, remove debug functionality"
    },
    "API10": {
        "name": "Unsafe Consumption of APIs",
        "description": "Trust third-party API responses without validation or allowlist",
        "endpoints": ["POST /api/shipping/quote"],
        "vulnerable": True,
        "fix": "Allowlist provider URLs, validate responses, use signatures"
    }
}

# Test Cases
TEST_CASES = {
    "API1": [
        {
            "name": "BOLA - Read other user's order",
            "endpoint": "GET /api/orders/2",
            "attack": "Login as User1, read order_id=2 (belongs to User2)",
            "vulnerable_result": "200 OK + order data",
            "secure_result": "403 Forbidden",
            "severity": "CRITICAL"
        },
        {
            "name": "BOLA - Read other user's profile",
            "endpoint": "GET /api/users/<user2_id>",
            "attack": "Login as User1, read User2's profile",
            "vulnerable_result": "200 OK + user data",
            "secure_result": "403 Forbidden",
            "severity": "CRITICAL"
        }
    ],
    "API2": [
        {
            "name": "Missing token rejection",
            "endpoint": "GET /api/orders/1 (no auth)",
            "attack": "Send request without JWT token",
            "vulnerable_result": "200 OK (request succeeds)",
            "secure_result": "401 Unauthorized",
            "severity": "CRITICAL"
        },
        {
            "name": "Tampered token acceptance",
            "endpoint": "GET /api/orders/1",
            "attack": "Use garbage JWT: 'this.is.not.a.jwt'",
            "vulnerable_result": "200 OK (invalid token accepted)",
            "secure_result": "401 Unauthorized",
            "severity": "CRITICAL"
        }
    ],
    "API3": [
        {
            "name": "Mass assignment - Become admin",
            "endpoint": "PATCH /api/users/1",
            "attack": 'Send {"is_admin": true, "role": "admin"}',
            "vulnerable_result": "User becomes admin",
            "secure_result": "Fields ignored, user stays normal",
            "severity": "CRITICAL"
        },
        {
            "name": "Password exposed in response",
            "endpoint": "GET /api/users/1",
            "attack": "Request user profile",
            "vulnerable_result": "Response includes plaintext password",
            "secure_result": "Password field not in response",
            "severity": "HIGH"
        }
    ],
    "API4": [
        {
            "name": "Huge pagination limit",
            "endpoint": "GET /api/products?limit=999999",
            "attack": "Request 999K products at once",
            "vulnerable_result": "200 OK (server tries to load all)",
            "secure_result": "400 Bad Request (limit capped at 100)",
            "severity": "HIGH"
        }
    ],
    "API5": [
        {
            "name": "Admin endpoint accessible to normal user",
            "endpoint": "GET /api/admin/users",
            "attack": "Login as normal User1, access admin list",
            "vulnerable_result": "200 OK + all users data",
            "secure_result": "403 Forbidden",
            "severity": "CRITICAL"
        },
        {
            "name": "Delete product without role check",
            "endpoint": "DELETE /api/products/1",
            "attack": "Normal user deletes product",
            "vulnerable_result": "200 OK (product deleted)",
            "secure_result": "403 Forbidden",
            "severity": "CRITICAL"
        }
    ],
    "API6": [
        {
            "name": "Confirm order without paying",
            "endpoint": "POST /api/orders/1/confirm",
            "attack": "Create order, confirm immediately (skip payment)",
            "vulnerable_result": "Order status: CONFIRMED (no payment taken)",
            "secure_result": "409 Conflict (must be PAID first)",
            "severity": "CRITICAL"
        }
    ],
    "API7": [
        {
            "name": "SSRF - Fetch internal localhost",
            "endpoint": "POST /api/utils/fetch-url",
            "attack": 'Send {"url": "http://127.0.0.1:5000/api/health"}',
            "vulnerable_result": "200 OK + internal response body",
            "secure_result": "403 Forbidden (localhost blocked)",
            "severity": "CRITICAL"
        }
    ],
    "API8": [
        {
            "name": "CORS wide open",
            "endpoint": "GET /api/products (with Origin header)",
            "attack": "Check Access-Control-Allow-Origin header",
            "vulnerable_result": "Access-Control-Allow-Origin: *",
            "secure_result": "Access-Control-Allow-Origin: restricted",
            "severity": "HIGH"
        }
    ],
    "API9": [
        {
            "name": "Old debug endpoint exposed",
            "endpoint": "GET /api/v1/debug/users (no auth)",
            "attack": "Access legacy debug endpoint",
            "vulnerable_result": "200 OK + all users data",
            "secure_result": "404 Not Found or 401 Unauthorized",
            "severity": "CRITICAL"
        }
    ],
    "API10": [
        {
            "name": "Trust third-party API response",
            "endpoint": "POST /api/shipping/quote",
            "attack": "Send arbitrary provider_url, trust quote response",
            "vulnerable_result": "Trusts any provider response",
            "secure_result": "Validates provider allowlist + response schema",
            "severity": "HIGH"
        }
    ]
}

def print_header():
    """Print report header"""
    print("\n" + "="*80)
    print("VulnShop API - OWASP Top 10 (2023) Test Report".center(80))
    print("="*80)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80 + "\n")

def print_vulnerability_summary():
    """Print vulnerability summary"""
    print("\n📊 VULNERABILITY SUMMARY\n")
    print(f"{'API':<6} {'Vulnerability':<40} {'Status':<15}")
    print("-" * 80)
    
    for api_num in sorted(VULNERABILITIES.keys()):
        vuln = VULNERABILITIES[api_num]
        status = "🔴 VULNERABLE" if vuln["vulnerable"] else "🟢 FIXED"
        print(f"{api_num:<6} {vuln['name']:<40} {status:<15}")

def print_vulnerability_details():
    """Print detailed vulnerability information"""
    print("\n\n📋 DETAILED VULNERABILITY BREAKDOWN\n")
    
    for api_num in sorted(VULNERABILITIES.keys()):
        vuln = VULNERABILITIES[api_num]
        print(f"\n{api_num}: {vuln['name']}")
        print("─" * 80)
        print(f"Description: {vuln['description']}")
        print(f"Affected Endpoints: {', '.join(vuln['endpoints'])}")
        print(f"Fix: {vuln['fix']}")

def print_test_cases():
    """Print all test cases"""
    print("\n\n🧪 TEST CASE MATRIX\n")
    
    total_tests = 0
    for api_num in sorted(TEST_CASES.keys()):
        tests = TEST_CASES[api_num]
        total_tests += len(tests)
        
        print(f"\n{api_num}: {VULNERABILITIES[api_num]['name']}")
        print("─" * 80)
        
        for idx, test in enumerate(tests, 1):
            print(f"\n  Test {idx}: {test['name']}")
            print(f"  Endpoint: {test['endpoint']}")
            print(f"  Attack: {test['attack']}")
            print(f"  Vulnerable Result: {test['vulnerable_result']}")
            print(f"  Secure Result: {test['secure_result']}")
            print(f"  Severity: {test['severity']}")
    
    print(f"\n\n📊 Total Tests: {total_tests}")

def print_endpoint_reference():
    """Print endpoint reference guide"""
    print("\n\n🔗 ENDPOINT REFERENCE GUIDE\n")
    print(f"{'Method':<8} {'Endpoint':<40} {'API #':<8} {'Status':<15}")
    print("─" * 80)
    
    endpoints = [
        ("GET", "/api/health", "-", "Safe"),
        ("POST", "/api/auth/login", "API2", "🔴 Vulnerable"),
        ("GET", "/api/users/<id>", "API1,API3", "🔴 Vulnerable"),
        ("PATCH", "/api/users/<id>", "API3", "🔴 Vulnerable"),
        ("GET", "/api/products", "API4", "🔴 Vulnerable"),
        ("DELETE", "/api/products/<id>", "API5", "🔴 Vulnerable"),
        ("POST", "/api/orders", "API3", "🔴 Vulnerable"),
        ("GET", "/api/orders/<id>", "API1", "🔴 Vulnerable"),
        ("POST", "/api/orders/<id>/pay", "API1", "🔴 Vulnerable"),
        ("POST", "/api/orders/<id>/confirm", "API6", "🔴 Vulnerable"),
        ("GET", "/api/admin/users", "API5", "🔴 Vulnerable"),
        ("POST", "/api/utils/fetch-url", "API7", "🔴 Vulnerable"),
        ("GET", "/api/v1/debug/users", "API9", "🔴 Vulnerable"),
        ("POST", "/api/shipping/quote", "API10", "🔴 Vulnerable"),
        ("POST", "/api/setup/reset", "API8", "⚠️ Intentional"),
    ]
    
    for method, endpoint, api, status in endpoints:
        print(f"{method:<8} {endpoint:<40} {api:<8} {status:<15}")

def print_postman_guide():
    """Print Postman collection guide"""
    print("\n\n📮 POSTMAN TEST SUITE GUIDE\n")
    print("Collection: VulnShop API Top 10 - Postman Lab")
    print("Environment: VulnShop - Local Lab")
    print("\nTest Execution Order:")
    print("  1. 00 - Setup → Reset DB")
    print("  2. 01 - Auth → Login User1 & User2")
    print("  3. 02 - API1 BOLA")
    print("  4. 03 - API2 Authentication")
    print("  5. 04 - API3 Property Level Auth")
    print("  6. 05 - API4 Resource Consumption")
    print("  7. 06 - API5 Function Level Auth")
    print("  8. 07 - API6 Business Flows")
    print("  9. 08 - API7 SSRF")
    print("  10. 09 - API8 Security Misconfiguration")
    print("  11. 10 - API9 Improper Inventory")
    print("  12. 11 - API10 Unsafe Consumption")
    print("\nExpected Results (vulnshop.py): ~17 FAIL, 2 PASS")
    print("Expected Results (secure_vulnshop.py): ~19 PASS")

def print_test_accounts():
    """Print seeded test accounts"""
    print("\n\n👤 SEEDED TEST ACCOUNTS\n")
    print(f"{'Email':<30} {'Password':<20} {'Role':<15}")
    print("─" * 80)
    accounts = [
        ("user1@example.com", "Password123", "user"),
        ("user2@example.com", "Password123", "user"),
        ("admin@example.com", "Admin123", "admin")
    ]
    
    for email, password, role in accounts:
        print(f"{email:<30} {password:<20} {role:<15}")

def print_seeded_data():
    """Print seeded database data"""
    print("\n\n📦 SEEDED DATABASE DATA\n")
    
    print("Users:")
    print(f"{'ID':<5} {'Email':<25} {'Balance':<15}")
    print("─" * 50)
    users = [
        (1, "user1@example.com", 1000),
        (2, "user2@example.com", 500),
        (3, "admin@example.com", 999999),
    ]
    for uid, email, balance in users:
        print(f"{uid:<5} {email:<25} ${balance/100:<15.2f}")
    
    print("\n\nProducts:")
    print(f"{'ID':<5} {'Name':<20} {'Price':<15} {'Stock':<10}")
    print("─" * 55)
    products = [
        (1, "Laptop", 120000, 5),
        (2, "Headphones", 5000, 25),
        (3, "Phone", 80000, 10),
    ]
    for pid, name, price, stock in products:
        print(f"{pid:<5} {name:<20} ${price/100:<15.2f} {stock:<10}")
    
    print("\n\nOrders:")
    print(f"{'ID':<5} {'User ID':<10} {'Product ID':<12} {'Qty':<5} {'Status':<15}")
    print("─" * 55)
    orders = [
        (1, 1, 1, 1, "CREATED"),
        (2, 2, 2, 2, "CREATED"),
    ]
    for oid, uid, pid, qty, status in orders:
        print(f"{oid:<5} {uid:<10} {pid:<12} {qty:<5} {status:<15}")

def print_comparison():
    """Print vulnerable vs secure comparison"""
    print("\n\n⚖️ VULNERABLE vs SECURE COMPARISON\n")
    print("API #  │ Vulnerable Version    │ Secure Version")
    print("───────┼───────────────────────┼─────────────────────────────────")
    
    comparisons = [
        ("API1", "BOLA (no checks)", "Ownership verification"),
        ("API2", "Plaintext + no rate limit", "Hashed + rate limiting"),
        ("API3", "Mass assignment + expose password", "Allowlist + no password"),
        ("API4", "No limit cap", "Max 100 items"),
        ("API5", "No role check", "Admin-only with role check"),
        ("API6", "Confirm without pay", "Enforce PAID status"),
        ("API7", "Fetch any URL", "Block private IPs"),
        ("API8", "DEBUG=on, CORS=*", "DEBUG=off, CORS restricted"),
        ("API9", "Debug endpoint exposed", "Debug endpoint removed"),
        ("API10", "Trust any provider", "Providerallowhlist + validate"),
    ]
    
    for api, vuln, secure in comparisons:
        print(f"{api:<6} │ {vuln:<21} │ {secure:<35}")

def print_recommendations():
    """Print security recommendations"""
    print("\n\n💡 SECURITY RECOMMENDATIONS\n")
    recommendations = [
        ("Authorization", "Always verify object ownership and user roles before returning/modifying resources"),
        ("Authentication", "Hash passwords, implement rate limiting (max 5 attempts/min), use strong secrets"),
        ("Input Validation", "Allowlist safe fields, enforce pagination caps, validate all inputs"),
        ("Business Logic", "Enforce state machines, validate workflow steps server-side"),
        ("Network Security", "Block internal IPs, metadata services (169.254.169.254), use allowlists"),
        ("Configuration", "Disable debug mode, restrict CORS, use secure defaults"),
        ("Inventory Management", "Remove old/debug endpoints, maintain API versioning"),
        ("Third-Party APIs", "Allowlist providers, validate responses, require signatures"),
        ("Error Handling", "Don't expose stack traces, log securely, return generic errors"),
        ("Monitoring", "Log all authentication, authorization failures, API abuse patterns"),
    ]
    
    for idx, (category, recommendation) in enumerate(recommendations, 1):
        print(f"{idx:2}. {category:<25} → {recommendation}")

def export_json(filename="vulnshop_report.json"):
    """Export report as JSON"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities": VULNERABILITIES,
        "test_cases": TEST_CASES,
        "total_vulnerabilities": len(VULNERABILITIES),
        "total_tests": sum(len(tests) for tests in TEST_CASES.values()),
    }
    
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n✅ Report exported to {filename}")

def main():
    """Generate complete report"""
    print_header()
    print_vulnerability_summary()
    print_vulnerability_details()
    print_test_cases()
    print_endpoint_reference()
    print_postman_guide()
    print_test_accounts()
    print_seeded_data()
    print_comparison()
    print_recommendations()
    
    # Export JSON
    export_json()
    
    print("\n\n" + "="*80)
    print("Report Complete - Ready for Lab Execution".center(80))
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
