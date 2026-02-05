# AegisForge Tool Integration Configuration Files

This directory contains comprehensive, production-ready configuration files for popular security testing tools integrated with the AegisForge platform.

## 📦 Contents

### 1. Postman Collection (`postman/`)
- **File**: `AegisForge_Complete_Collection.json` (142 KB, 4,733 lines)
- **Contains**: 141+ API requests
- **Features**:
  - 87 Red Team (vulnerable) requests
  - 54 Blue Team (secure) requests
  - Automated test scripts for each request
  - Environment variable support
  - JWT token management
  - CSRF token handling

**Categories Covered**:
- Authentication (login, register, brute force, weak passwords)
- SQL Injection (boolean, time-based, UNION attacks)
- XSS (reflected, stored, DOM-based)
- Access Control (IDOR, privilege escalation, BOLA)
- Command Injection
- XXE (XML External Entity)
- SSRF (Server-Side Request Forgery)
- Open Redirect
- Business Logic vulnerabilities
- Information Disclosure
- File Upload
- CSRF Protection

**Usage**:
```bash
# Import into Postman
1. Open Postman
2. File > Import
3. Select AegisForge_Complete_Collection.json
4. Set environment variables:
   - red_base_url: http://localhost:5000
   - blue_base_url: http://localhost:5001
```

### 2. Burp Suite Configuration (`burp/`)

#### A. Project Configuration
- **File**: `AegisForge_Project.json` (9 KB, 364 lines)
- **Features**:
  - Target scope for Red Team (port 5000) and Blue Team (port 5001)
  - Scanner settings for all OWASP vulnerabilities
  - Active and passive scan configurations
  - Session handling rules
  - Proxy settings

**Usage**:
```bash
# Import into Burp Suite
1. Open Burp Suite Professional
2. Project > Project options > Load project file
3. Select AegisForge_Project.json
```

#### B. Intruder Payloads
- **File**: `AegisForge_Intruder_Payloads.txt` (7 KB, 380 lines)
- **Contains**:
  - 20+ SQL injection payloads
  - 20+ XSS payloads
  - 10+ Command injection payloads
  - 10+ Path traversal payloads
  - IDOR/access control payloads
  - SSRF payloads
  - Open redirect payloads
  - XXE payloads
  - Authentication bypass payloads
  - Header injection payloads
  - Business logic payloads
  - File upload payloads
  - NoSQL injection payloads
  - LDAP injection payloads
  - Template injection payloads

**Usage**:
```bash
# Load in Burp Intruder
1. Send request to Intruder (Ctrl+I)
2. Set attack positions
3. Payloads tab > Load > Select AegisForge_Intruder_Payloads.txt
4. Start attack
```

### 3. OWASP ZAP Automation (`zap/`)
- **File**: `automation_scan.yaml` (7.7 KB, 264 lines)
- **Features**:
  - Complete automation framework configuration
  - Spider (traditional and AJAX)
  - Passive and active scanning
  - Authentication setup
  - Custom scan policies
  - Multiple report formats (JSON, HTML, XML, Markdown)

**Scan Policies**:
- SQL Injection (all variants)
- XSS (reflected, stored, DOM)
- Command Injection
- Path Traversal
- XXE
- SSRF
- Authentication vulnerabilities
- Access control issues
- Information disclosure

**Usage**:
```bash
# Run automation scan
zap.sh -cmd -autorun /path/to/automation_scan.yaml

# Or with Docker
docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap.sh \
  -cmd -autorun /zap/wrk/zap/automation_scan.yaml
```

**Output**:
- `aegisforge_zap_report.json`
- `aegisforge_zap_report.html`
- `aegisforge_zap_report.xml`
- `aegisforge_zap_report.md`
- `scan_summary.txt`

### 4. SQLMap Testing Script (`sqlmap/`)
- **File**: `aegisforge_tests.sh` (15 KB, 327 lines, executable)
- **Features**:
  - 20+ automated SQLMap tests
  - Boolean-based blind SQL injection
  - Time-based blind SQL injection
  - UNION-based SQL injection
  - Error-based SQL injection
  - Stacked queries
  - Database enumeration
  - Data extraction
  - Advanced features (OS shell, file read, privileges)
  - WAF detection and bypass
  - Colored output and progress tracking
  - Comprehensive logging

**Test Categories**:
1. Boolean-Based Blind SQLi (4 tests)
2. Time-Based Blind SQLi (4 tests)
3. UNION-Based SQLi (5 tests)
4. Error-Based SQLi (2 tests)
5. Stacked Queries (1 test)
6. All Techniques Combined (3 tests)
7. Advanced Features (4 tests)
8. POST-based SQLi (1 test)
9. WAF Detection/Bypass (2 tests)

**Usage**:
```bash
# Run all tests
cd /home/runner/work/aegisforgee/aegisforgee/sqlmap
./aegisforge_tests.sh

# Results saved in ./sqlmap_results/
```

### 5. FFUF Fuzzing Script (`ffuf/`)
- **File**: `aegisforge_fuzzing.sh** (19 KB, 582 lines, executable)
- **Features**:
  - Directory and file fuzzing
  - API endpoint discovery
  - Parameter fuzzing (GET and POST)
  - SQL injection fuzzing
  - XSS fuzzing
  - Path traversal fuzzing
  - Command injection fuzzing
  - SSRF fuzzing
  - IDOR/access control enumeration
  - Header injection fuzzing
  - Multi-parameter fuzzing
  - Automatic wordlist generation
  - JSON output for all tests
  - Colored output and progress tracking

**Test Categories**:
1. Directory Fuzzing (3 tests)
2. Parameter Fuzzing (2 tests)
3. SQL Injection Fuzzing (3 tests)
4. XSS Fuzzing (2 tests)
5. Path Traversal Fuzzing (1 test)
6. Command Injection Fuzzing (1 test)
7. SSRF Fuzzing (1 test)
8. IDOR/Access Control Fuzzing (1 test)
9. Header Injection Fuzzing (3 tests)
10. Multi-parameter Fuzzing (1 test)

**Custom Wordlists Generated**:
- `api_endpoints.txt` (30+ entries)
- `directories.txt` (40+ entries)
- `parameters.txt` (50+ entries)
- `sqli_payloads.txt` (30+ payloads)
- `xss_payloads.txt` (25+ payloads)
- `path_traversal.txt` (40+ payloads)
- `command_injection.txt` (25+ payloads)
- `ssrf_payloads.txt` (15+ payloads)
- `header_values.txt` (20+ values)

**Usage**:
```bash
# Run all fuzzing tests
cd /home/runner/work/aegisforgee/aegisforgee/ffuf
./aegisforge_fuzzing.sh

# Results saved in ./ffuf_results/
# Wordlists saved in ./wordlists/
```

## 🎯 Testing Workflow

### Recommended Testing Sequence:

1. **Discovery & Reconnaissance**
   ```bash
   # Start with FFUF for discovery
   cd ffuf && ./aegisforge_fuzzing.sh
   ```

2. **Comprehensive Scanning**
   ```bash
   # Run OWASP ZAP automation
   zap.sh -cmd -autorun /path/to/zap/automation_scan.yaml
   ```

3. **Targeted SQL Injection**
   ```bash
   # Use SQLMap for deep SQLi testing
   cd sqlmap && ./aegisforge_tests.sh
   ```

4. **Manual Testing**
   ```bash
   # Use Postman for manual API testing
   # Import AegisForge_Complete_Collection.json
   ```

5. **Advanced Manual Testing**
   ```bash
   # Use Burp Suite for advanced testing
   # Load AegisForge_Project.json
   # Use AegisForge_Intruder_Payloads.txt
   ```

## 🔴 Red Team vs 🔵 Blue Team Testing

All configurations support testing both:

- **Red Team (Port 5000)**: Intentionally vulnerable endpoints
  - Use these to learn exploitation techniques
  - Practice identifying vulnerabilities
  - Understand how attacks work

- **Blue Team (Port 5001)**: Secure implementations
  - Verify defenses are effective
  - Compare with vulnerable versions
  - Learn defensive coding patterns

## 📊 Output & Reporting

### Expected Output Locations:

- **Postman**: Built-in test results and Newman CLI reports
- **Burp**: Scan reports in Burp UI or exported HTML/XML
- **ZAP**: `zap/aegisforge_zap_report.*` (multiple formats)
- **SQLMap**: `sqlmap/sqlmap_results/`
- **FFUF**: `ffuf/ffuf_results/`

## 🛡️ Security Notes

**⚠️ WARNING**: These configurations are designed for testing in controlled environments only!

- Never use these tools against production systems without authorization
- Always test in isolated lab environments
- Red Team endpoints are intentionally vulnerable - do NOT deploy to internet-facing servers
- Blue Team endpoints demonstrate secure practices but should still be tested in isolated environments

## 📚 Additional Resources

- **Postman Documentation**: https://learning.postman.com/
- **Burp Suite Guide**: `../BURP_SUITE_GUIDE.md`
- **OWASP ZAP Guide**: `../OWASP_ZAP_GUIDE.md`
- **SQLMap Guide**: `../SQLMAP_GUIDE.md`
- **FFUF Guide**: `../FFUF_GUIDE.md`

## 🔧 Prerequisites

### Required Tools:
- Postman Desktop App (latest version)
- Burp Suite Professional (or Community Edition)
- OWASP ZAP (2.11.0+)
- SQLMap (latest version)
- FFUF (latest version)
- Python 3.8+
- Bash shell (Linux/macOS or WSL on Windows)

### Installation:

```bash
# Postman
# Download from: https://www.postman.com/downloads/

# Burp Suite
# Download from: https://portswigger.net/burp/communitydownload

# OWASP ZAP
# Download from: https://www.zaproxy.org/download/

# SQLMap (Python)
pip install sqlmap
# Or: git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git

# FFUF (Go)
go install github.com/ffuf/ffuf@latest
# Or download from: https://github.com/ffuf/ffuf/releases
```

## 🚀 Quick Start

```bash
# 1. Start AegisForge servers
docker-compose up -d  # Or use startup scripts

# 2. Import Postman collection and test basic functionality
# File > Import > AegisForge_Complete_Collection.json

# 3. Run automated scans
cd zap && zap.sh -cmd -autorun automation_scan.yaml
cd ../sqlmap && ./aegisforge_tests.sh
cd ../ffuf && ./aegisforge_fuzzing.sh

# 4. Load Burp configuration for manual testing
# Project > Load project file > AegisForge_Project.json

# 5. Review results in respective output directories
```

## 📝 Version Information

- **Postman Collection**: v2.1.0 schema, 141 requests
- **Burp Configuration**: Compatible with Burp Suite Pro 2023.x+
- **ZAP Automation**: ZAP 2.11.0+ automation framework
- **SQLMap Script**: Compatible with SQLMap 1.7+
- **FFUF Script**: Compatible with FFUF 2.0+

## 🤝 Contributing

To add new tests or improve configurations:

1. Follow existing patterns and naming conventions
2. Test thoroughly in isolated environment
3. Update this README with new features
4. Document any new dependencies

## 📄 License

These configurations are part of the AegisForge security testing platform.
Use responsibly and ethically.

---

**Last Updated**: 2025-02-05
**Maintained by**: AegisForge Security Team
