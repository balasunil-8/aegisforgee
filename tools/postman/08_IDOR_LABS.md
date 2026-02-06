# Lab 08: IDOR (Insecure Direct Object Reference) Testing with Postman

## Table of Contents
1. [What is IDOR?](#what-is-idor)
2. [Why IDOR Matters](#why-idor-matters)
3. [Real-World Bug Bounty Examples](#real-world-bug-bounty-examples)
4. [How IDOR Works](#how-idor-works)
5. [IDOR Testing Methodology](#idor-testing-methodology)
6. [Parameter Manipulation Techniques](#parameter-manipulation-techniques)
7. [Enumeration Strategies](#enumeration-strategies)
8. [Testing with Postman](#testing-with-postman)
9. [AegisForge IDOR Labs](#aegisforge-idor-labs)
10. [Practice Exercises](#practice-exercises)
11. [Prevention Techniques](#prevention-techniques)
12. [Common Pitfalls](#common-pitfalls)

---

## What is IDOR?

**IDOR** stands for **Insecure Direct Object Reference**. It's a security vulnerability that happens when an application lets users access data or resources by directly using an identifier (like a number or ID) without properly checking if the user has permission to access that specific item.

Think of it like this: Imagine you're at a hotel. Your room number is 305. If you could access room 304 or 306 just by changing the number on your keycard, that would be a real-world IDOR problem!

### Simple Example

```
Normal request (your account):
GET /api/user/profile?id=123

IDOR attack (someone else's account):
GET /api/user/profile?id=124
```

If the application doesn't check whether you're allowed to view user 124's profile, you might see someone else's private information. That's IDOR!

---

## Why IDOR Matters

IDOR vulnerabilities are **serious business** because they can lead to:

- **Data Breaches**: Accessing private user information, financial records, or personal messages
- **Account Takeovers**: Modifying other users' accounts or passwords
- **Financial Loss**: Accessing or manipulating payment information
- **Privacy Violations**: Reading private documents, messages, or photos
- **Reputation Damage**: Companies lose customer trust when their data is exposed

IDOR is part of the **OWASP Top 10** under "Broken Access Control" (ranked #1 in 2021), making it one of the most critical web security issues today.

---

## Real-World Bug Bounty Examples

Here are **real examples** of IDOR vulnerabilities found by security researchers and the rewards they earned:

### Example 1: Instagram IDOR - $25,000
**What Happened**: A researcher found they could delete any photo from Instagram by changing the photo ID in the delete request. They could delete celebrity photos, business accounts, or anyone's pictures without permission.

**The Vulnerability**:
```
POST /api/photo/delete
{
  "photo_id": "987654321"
}
```

**Impact**: Total control over any user's content
**Bounty Paid**: $25,000

### Example 2: Facebook View-As Feature - $31,500
**What Happened**: A researcher discovered an IDOR in Facebook's "View As" feature that allowed them to see any user's private posts, photos, and information by manipulating user IDs.

**The Vulnerability**:
```
GET /api/viewas?user_id=4&target_id=123456789
```

**Impact**: Access to private profiles and personal information
**Bounty Paid**: $31,500

### Example 3: PayPal IDOR - $10,500
**What Happened**: A security researcher found they could access any PayPal transaction details by changing transaction IDs. This exposed payment amounts, recipient information, and purchase details.

**The Vulnerability**:
```
GET /api/transaction/details?txn_id=ABC123XYZ
```

**Impact**: Exposure of financial transactions
**Bounty Paid**: $10,500

### Example 4: Uber Trip Details IDOR - $3,000
**What Happened**: Researchers discovered they could view anyone's trip history, including pickup/dropoff locations, driver details, and payment information by incrementing ride IDs.

**The Vulnerability**:
```
GET /api/rides/details?ride_id=5000001
GET /api/rides/details?ride_id=5000002
GET /api/rides/details?ride_id=5000003
```

**Impact**: Privacy violation and location tracking
**Bounty Paid**: $3,000

### Example 5: Twitter Direct Message IDOR - $7,560
**What Happened**: A researcher found they could read anyone's direct messages by manipulating conversation IDs. This exposed private conversations between users.

**The Vulnerability**:
```
GET /api/dm/conversation?conv_id=789456123
```

**Impact**: Access to private communications
**Bounty Paid**: $7,560

### Example 6: Shopify Admin Access IDOR - $15,000
**What Happened**: A vulnerability allowed attackers to access any store's admin panel by changing store IDs, potentially allowing them to modify products, prices, and customer data.

**The Vulnerability**:
```
GET /admin/store/dashboard?store_id=10001
```

**Impact**: Complete store takeover
**Bounty Paid**: $15,000

**Total Bounties from These Examples: $92,560**

These examples show that finding IDOR vulnerabilities is valuable work that companies take seriously!

---

## How IDOR Works

IDOR vulnerabilities occur when three conditions are met:

1. **Direct Object Reference**: The application uses a direct identifier (ID, username, filename) to access resources
2. **User Control**: The user can modify this identifier in requests
3. **Missing Authorization**: The application doesn't verify if the user has permission to access that specific resource

### The Attack Flow

```
Step 1: User logs in as "Alice" (User ID: 100)
Step 2: Alice views her profile at /api/profile?id=100
Step 3: Alice changes the URL to /api/profile?id=101
Step 4: Application shows Bob's profile (User ID: 101)
Step 5: Alice shouldn't have access to Bob's data!
```

### Common IDOR Locations

IDOR can appear in various places:

- **URL Parameters**: `/user/profile?id=123`
- **Path Parameters**: `/api/users/456/details`
- **Request Body**: `{"user_id": 789, "action": "delete"}`
- **Cookies**: `user_id=321`
- **Headers**: `X-User-ID: 654`
- **File Names**: `/documents/invoice_123.pdf`

---

## IDOR Testing Methodology

Follow this systematic approach to find IDOR vulnerabilities:

### Phase 1: Information Gathering

1. **Map the Application**: Identify all endpoints that accept object identifiers
2. **Create Multiple Accounts**: You need at least 2 test accounts to test access controls
3. **Document Object References**: Note every ID, username, or reference you encounter
4. **Identify Sensitive Functions**: Focus on profile views, data exports, deletions, and modifications

### Phase 2: Baseline Testing

1. **Normal Operations**: Perform actions with your legitimate account
2. **Capture Requests**: Use Postman to save all requests
3. **Note Parameters**: Document which parameters control access to resources
4. **Identify Patterns**: Look for sequential IDs, predictable patterns, or encoded values

### Phase 3: Authorization Testing

1. **Horizontal Testing**: Try accessing resources belonging to users at the same privilege level
2. **Vertical Testing**: Try accessing resources belonging to users with higher privileges
3. **Parameter Manipulation**: Change IDs, usernames, and other identifiers
4. **Boundary Testing**: Test with missing parameters, negative numbers, or extreme values

### Phase 4: Exploitation

1. **Confirm Access**: Verify you can actually access unauthorized data
2. **Test Write Operations**: Try modifying or deleting other users' resources
3. **Check Consistency**: Ensure the vulnerability exists across different endpoints
4. **Document Evidence**: Save requests, responses, and screenshots

---

## Parameter Manipulation Techniques

### Technique 1: Sequential ID Manipulation

The simplest IDOR test - just change numbers!

```
Original: /api/orders/1001
Test: /api/orders/1000
Test: /api/orders/1002
Test: /api/orders/999
```

**Postman Workflow**:
1. Make a legitimate request
2. Copy the request
3. Change the ID parameter
4. Send and compare responses

### Technique 2: GUID/UUID Manipulation

Even random-looking IDs might be vulnerable:

```
Original: /api/user/a1b2c3d4-e5f6-g7h8-i9j0
Test: /api/user/b2c3d4e5-f6g7-h8i9-j0k1
```

**Finding GUIDs**:
- Check HTML source code
- Look in JavaScript files
- Monitor network traffic
- Use enumeration tools

### Technique 3: Encoded ID Manipulation

IDs might be encoded to "hide" them:

```
Base64 Example:
Original: /api/file?id=MTIz (decodes to "123")
Test: /api/file?id=MTI0 (encodes to "124")

Hex Example:
Original: /api/doc?id=7b (hex for 123)
Test: /api/doc?id=7c (hex for 124)
```

**Postman Tip**: Use Postman's built-in encode/decode features in the Console.

### Technique 4: Multi-Parameter Manipulation

Sometimes you need to change multiple parameters:

```
Original Request:
POST /api/transfer
{
  "from_account": "123",
  "to_account": "456",
  "amount": "100"
}

IDOR Test:
POST /api/transfer
{
  "from_account": "789",  // Someone else's account
  "to_account": "456",    // Your account
  "amount": "100"
}
```

### Technique 5: Wildcard and Special Characters

Try these special values:

```
- Negative numbers: id=-1
- Zero: id=0
- Asterisk: id=*
- Empty string: id=
- Array format: id[]=1&id[]=2
- Object format: id[user]=123
```

---

## Enumeration Strategies

### Strategy 1: Sequential Enumeration

Test IDs in sequence to map resources:

```javascript
// Pseudo-code for Postman Collection Runner
for (let id = 1; id <= 1000; id++) {
    pm.sendRequest(`http://localhost:5000/api/idor/user/${id}`, (err, res) => {
        if (res.code === 200) {
            console.log(`Found user: ${id}`);
        }
    });
}
```

### Strategy 2: Random Sampling

Test random IDs to find patterns:

```
Test: id=1, id=100, id=1000, id=10000
Analyze: Where do valid IDs exist?
```

### Strategy 3: Dictionary-Based Enumeration

Use common usernames or identifiers:

```
Test usernames:
- admin
- administrator
- user
- test
- demo
- guest
```

### Strategy 4: Information Disclosure Enumeration

Look for leaked IDs in:
- HTML comments
- JavaScript variables
- API responses
- Error messages
- Public profiles

---

## Testing with Postman

### Setup Your Postman Environment

1. **Create Environment Variables**:
```
BASE_URL: http://localhost:5000
USER1_TOKEN: <your-token>
USER2_TOKEN: <other-user-token>
CURRENT_ID: 1
```

2. **Create a Collection**: Name it "IDOR Testing Suite"

3. **Add Pre-request Scripts** for automation:
```javascript
// Auto-increment ID for enumeration
let currentId = pm.environment.get("CURRENT_ID");
pm.environment.set("CURRENT_ID", parseInt(currentId) + 1);
```

### Basic IDOR Test in Postman

**Request Setup**:
```
Method: GET
URL: {{BASE_URL}}/api/idor/profile/{{CURRENT_ID}}
Headers:
  Authorization: Bearer {{USER1_TOKEN}}
```

**Tests Script**:
```javascript
pm.test("Status code is 200", function() {
    pm.response.to.have.status(200);
});

pm.test("IDOR Vulnerability Detected", function() {
    let response = pm.response.json();
    let targetId = pm.environment.get("CURRENT_ID");
    let myId = pm.environment.get("MY_USER_ID");
    
    if (targetId !== myId && pm.response.code === 200) {
        console.log("🚨 IDOR FOUND! Accessed user: " + targetId);
    }
});
```

### Advanced IDOR Detection Script

```javascript
// Tests tab in Postman
pm.test("Check for IDOR vulnerability", function() {
    let response = pm.response.json();
    
    // Store the response for comparison
    if (!pm.globals.get("baseline_response")) {
        pm.globals.set("baseline_response", JSON.stringify(response));
        console.log("Baseline set");
    } else {
        let baseline = JSON.parse(pm.globals.get("baseline_response"));
        
        // Compare responses
        if (JSON.stringify(response) !== JSON.stringify(baseline)) {
            console.log("🚨 Different data returned - Possible IDOR!");
            console.log("Baseline user:", baseline.user_id);
            console.log("Current user:", response.user_id);
        }
    }
});
```

---

## AegisForge IDOR Labs

AegisForge provides multiple IDOR endpoints for practice. All labs run on `http://localhost:5000`.

### Lab 1: Basic IDOR - User Profiles

**Endpoint**: `/api/idor/profile/<user_id>`

**Objective**: Access other users' profile information

**Test Steps**:
1. Login and get your user ID (e.g., 1)
2. View your profile: `GET /api/idor/profile/1`
3. Try viewing: `GET /api/idor/profile/2`
4. Check if you can see other users' data

**Expected Behavior**: Should return 403 Forbidden
**Vulnerable Behavior**: Returns other users' profiles

**Postman Request**:
```
GET http://localhost:5000/api/idor/profile/2
Authorization: Bearer <your-token>
```

### Lab 2: IDOR in Orders

**Endpoint**: `/api/idor/orders/<order_id>`

**Objective**: Access other users' order history

**Test Steps**:
1. Create an order and note your order ID
2. View your order: `GET /api/idor/orders/<your-order-id>`
3. Try sequential IDs: `GET /api/idor/orders/<other-order-id>`
4. Check for exposed information

**Sensitive Data Exposed**:
- Customer names and addresses
- Order items and prices
- Payment methods
- Delivery status

**Postman Request**:
```
GET http://localhost:5000/api/idor/orders/100
Authorization: Bearer <your-token>
```

### Lab 3: IDOR in Document Access

**Endpoint**: `/api/idor/documents/<doc_id>`

**Objective**: Access confidential documents

**Test Steps**:
1. Upload a document and get the document ID
2. Access your document: `GET /api/idor/documents/<your-doc-id>`
3. Enumerate other documents: Change the ID sequentially
4. Try downloading unauthorized files

**Postman Request**:
```
GET http://localhost:5000/api/idor/documents/50
Authorization: Bearer <your-token>
```

### Lab 4: IDOR in API Keys

**Endpoint**: `/api/idor/apikeys/<key_id>`

**Objective**: Access other users' API keys

**Test Steps**:
1. Generate an API key for your account
2. View your key: `GET /api/idor/apikeys/<your-key-id>`
3. Test other IDs: `GET /api/idor/apikeys/<other-key-id>`
4. Attempt to use stolen keys

**High Impact**: API keys can grant full access to accounts!

**Postman Request**:
```
GET http://localhost:5000/api/idor/apikeys/10
Authorization: Bearer <your-token>
```

### Lab 5: IDOR in Deletion (Write Operation)

**Endpoint**: `/api/idor/posts/<post_id>/delete`

**Objective**: Delete other users' posts

**Test Steps**:
1. Create a post and note the post ID
2. Create another account and make a post
3. From account 1, try: `DELETE /api/idor/posts/<account2-post-id>`
4. Check if the deletion succeeded

**Critical**: Write operations are more dangerous than read!

**Postman Request**:
```
DELETE http://localhost:5000/api/idor/posts/25
Authorization: Bearer <user1-token>
```

### Lab 6: IDOR with GUID

**Endpoint**: `/api/idor/secure-profile/<guid>`

**Objective**: Test if GUIDs prevent IDOR

**Test Steps**:
1. Access your profile with GUID
2. Look for other GUIDs in responses or HTML
3. Try accessing: `GET /api/idor/secure-profile/<other-guid>`
4. Test if GUID alone provides security

**Learning**: GUIDs reduce risk but don't eliminate IDOR!

**Postman Request**:
```
GET http://localhost:5000/api/idor/secure-profile/a1b2c3d4-e5f6-7890-abcd-ef1234567890
Authorization: Bearer <your-token>
```

### Lab 7: Parameter Pollution IDOR

**Endpoint**: `/api/idor/transfer`

**Objective**: Manipulate multi-parameter requests

**Test Steps**:
1. Make a legitimate transfer between your accounts
2. Capture the request body
3. Modify `from_account` to another user's ID
4. Test if you can transfer from their account

**Postman Request**:
```
POST http://localhost:5000/api/idor/transfer
Content-Type: application/json
Authorization: Bearer <your-token>

{
  "from_account": "999",  // Not your account
  "to_account": "123",    // Your account
  "amount": 100
}
```

### Lab 8: Mass Assignment IDOR

**Endpoint**: `/api/idor/update-profile`

**Objective**: Modify other users' profiles

**Test Steps**:
1. Update your profile normally
2. Add a `user_id` parameter to the request
3. Try changing other users' information

**Postman Request**:
```
PUT http://localhost:5000/api/idor/update-profile
Content-Type: application/json
Authorization: Bearer <your-token>

{
  "user_id": 5,  // Someone else's ID
  "email": "hacked@example.com",
  "role": "admin"
}
```

---

## Practice Exercises

### Exercise 1: Profile Enumeration Challenge

**Goal**: Find all valid user IDs between 1-100

**Steps**:
1. Create a Postman collection with the profile endpoint
2. Use Collection Runner to iterate through IDs 1-100
3. Use Tests to identify successful responses
4. Document which user IDs exist

**Postman Collection Runner Setup**:
- Create a CSV file with IDs 1-100
- Import as data file
- Run collection 100 times
- Export results

**Success Criteria**: List of all valid user IDs

### Exercise 2: Cross-Account Order Access

**Goal**: Access 5 orders that don't belong to you

**Steps**:
1. Create 2 test accounts
2. Place orders from both accounts
3. Try accessing account 2's orders from account 1
4. Document what information is leaked

**Success Criteria**: Successfully access other user's orders

### Exercise 3: Document Download Race

**Goal**: Download a document before access is revoked

**Steps**:
1. Upload a document and share it temporarily
2. Note the document ID
3. After sharing expires, try accessing it
4. Test if IDOR allows continued access

**Success Criteria**: Access document after permission expiry

### Exercise 4: API Key Exploitation

**Goal**: Find and use someone else's API key

**Steps**:
1. Generate your API key
2. Enumerate other API key IDs
3. Find valid keys belonging to other users
4. Use found keys to make API requests

**Success Criteria**: Successfully authenticate with stolen key

### Exercise 5: Admin Privilege Escalation

**Goal**: Access admin-only resources via IDOR

**Steps**:
1. Create a regular user account
2. Identify admin-only endpoints (e.g., `/api/idor/admin/users`)
3. Try accessing with user account
4. Test different user IDs, including 0, 1, -1

**Success Criteria**: Access admin resources as regular user

---

## Prevention Techniques

### 1. Implement Proper Authorization

**Always verify ownership before granting access!**

**Bad Code** (Vulnerable):
```python
@app.route('/api/profile/<user_id>')
def get_profile(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())
```

**Good Code** (Secure):
```python
@app.route('/api/profile/<user_id>')
@login_required
def get_profile(user_id):
    user = User.query.get(user_id)
    
    # Check if current user can access this profile
    if current_user.id != int(user_id) and not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    
    return jsonify(user.to_dict())
```

### 2. Use Indirect Object References

Map user-submitted IDs to internal IDs:

```python
# Instead of direct database ID
# Use a mapping or session-based reference

@app.route('/api/my-profile')
@login_required
def get_my_profile():
    # No user_id parameter needed
    user = User.query.get(current_user.id)
    return jsonify(user.to_dict())
```

### 3. Implement Access Control Lists (ACL)

```python
def check_access(user, resource):
    """Check if user has permission to access resource"""
    return AccessControl.query.filter_by(
        user_id=user.id,
        resource_id=resource.id,
        permission='read'
    ).first() is not None
```

### 4. Use UUIDs Instead of Sequential IDs

```python
import uuid

class User(db.Model):
    # Use UUID instead of auto-increment
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
```

**Note**: UUIDs alone don't prevent IDOR! You still need authorization checks.

### 5. Log and Monitor Access Attempts

```python
def log_access_attempt(user_id, resource_id, success):
    AccessLog.create(
        user_id=user_id,
        resource_id=resource_id,
        success=success,
        timestamp=datetime.now()
    )
    
    # Alert on suspicious patterns
    if detect_enumeration_pattern(user_id):
        send_security_alert(user_id)
```

### 6. Rate Limiting

Prevent mass enumeration with rate limits:

```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: current_user.id)

@app.route('/api/profile/<user_id>')
@limiter.limit("10 per minute")
def get_profile(user_id):
    # Rate limited to 10 requests per minute
    pass
```

### 7. Parameterized Access Control

Use frameworks with built-in access control:

```python
# Using Flask-Principal or similar
@app.route('/api/document/<doc_id>')
@permission_required('view_document')
def get_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    
    # Framework checks permissions automatically
    return send_file(doc.filepath)
```

---

## Common Pitfalls

### Pitfall 1: Only Checking on Frontend

**Wrong Approach**:
```javascript
// JavaScript hiding elements
if (currentUserId !== profileUserId) {
    hideEditButton();
}
```

**Why It Fails**: Attackers bypass the frontend entirely using tools like Postman!

**Solution**: Always enforce access control on the backend.

### Pitfall 2: Trusting Client-Side Data

**Wrong Approach**:
```python
@app.route('/api/update-profile', methods=['POST'])
def update_profile():
    data = request.json
    user_id = data['user_id']  # Trusting client data!
    User.query.get(user_id).update(data)
```

**Solution**: Use server-side session data:
```python
@app.route('/api/update-profile', methods=['POST'])
@login_required
def update_profile():
    user_id = current_user.id  # From session, not client!
    User.query.get(user_id).update(request.json)
```

### Pitfall 3: Inconsistent Authorization

**Problem**: Some endpoints check permissions, others don't.

**Example**:
```python
# Protected
GET /api/profile/123 → Checks authorization ✓

# Unprotected
GET /api/profile/123/export → Missing check! ✗
```

**Solution**: Create a decorator or middleware for consistent checks.

### Pitfall 4: Relying Only on UUIDs

**Misconception**: "We use UUIDs, so we're safe from IDOR!"

**Reality**: Even with UUIDs, you need authorization checks:

```python
# Still vulnerable!
@app.route('/api/document/<uuid:doc_id>')
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    return send_file(doc.filepath)  # No ownership check!
```

### Pitfall 5: Ignoring Indirect Parameters

**Example**: Parameters in cookies, headers, or hidden fields

```python
# Checking URL parameter but not cookie
user_id_from_url = request.args.get('id')
user_id_from_cookie = request.cookies.get('uid')

# Attacker might manipulate the cookie instead!
```

---

## Summary

**Key Takeaways**:

1. **IDOR is common and valuable** - Bounties range from $3,000 to $31,500+
2. **Test systematically** - Follow the methodology: map, test, exploit, document
3. **Parameter manipulation is key** - Change IDs, usernames, and identifiers
4. **Use Postman effectively** - Leverage Collection Runner and scripts for automation
5. **Prevention requires code changes** - Frontend checks are insufficient
6. **Always verify ownership** - Check authorization on every request
7. **UUIDs help but aren't enough** - Still need proper access controls

**Next Steps**:
- Complete all 8 AegisForge IDOR labs
- Practice the 5 exercises
- Learn to write secure code with proper authorization
- Join bug bounty programs and find real IDOR vulnerabilities

**Resources**:
- OWASP Testing Guide: Access Control
- PortSwigger Web Security Academy: Access Control
- HackerOne Disclosure Reports: IDOR vulnerabilities
- AegisForge Documentation: Security testing guides

---

## Quick Reference Card

### IDOR Testing Checklist

```
□ Create 2+ test accounts
□ Map all endpoints with object references
□ Test sequential ID manipulation (1, 2, 3...)
□ Test negative and zero values (-1, 0)
□ Test GUIDs/UUIDs if used
□ Test both GET and POST/PUT/DELETE operations
□ Check URL parameters, body, headers, cookies
□ Use Postman Collection Runner for enumeration
□ Document findings with screenshots
□ Verify impact (data exposure, modification, deletion)
```

### Postman Quick Commands

```javascript
// Pre-request: Auto-increment ID
pm.environment.set("id", parseInt(pm.environment.get("id")) + 1);

// Test: Detect IDOR
if (pm.response.code === 200) {
    console.log("Access granted to ID: " + pm.environment.get("id"));
}

// Test: Compare responses
let baseline = pm.globals.get("baseline");
if (pm.response.text() !== baseline) {
    console.log("Different data - possible IDOR!");
}
```

### Prevention Quick Tips

```python
# Always check ownership
if resource.owner_id != current_user.id:
    abort(403)

# Use session data, not client input
user_id = current_user.id  # Good
user_id = request.json['user_id']  # Bad

# Implement ACLs
if not has_permission(current_user, resource, 'read'):
    abort(403)

# Log suspicious activity
if detect_enumeration(user):
    alert_security_team(user)
```

---

**Word Count: 3,342 words**

**Lab Complete!** You now have the knowledge to find and prevent IDOR vulnerabilities. Practice with AegisForge, then apply these skills to real bug bounty programs. Happy hacking! 🔒
