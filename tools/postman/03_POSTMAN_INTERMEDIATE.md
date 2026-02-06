# Postman Intermediate - Variables, Scripts, and Automation

## Table of Contents
1. [Introduction](#introduction)
2. [Variables Deep Dive](#variables-deep-dive)
3. [Pre-request Scripts](#pre-request-scripts)
4. [Test Scripts](#test-scripts)
5. [Authentication Types](#authentication-types)
6. [Chaining Requests](#chaining-requests)
7. [Data-Driven Testing](#data-driven-testing)
8. [Practical Examples](#practical-examples)

---

## Introduction

Welcome to Postman Intermediate! Now that you understand the basics, we'll explore powerful features that transform Postman from a simple request sender into an automated testing powerhouse.

**What you'll learn:**
- Using variables effectively across different scopes
- Writing JavaScript to automate tasks
- Testing responses programmatically
- Handling different authentication methods
- Chaining requests together
- Running tests with different data sets

**Prerequisites:**
- Completed Postman Basics guide
- Comfortable sending GET/POST requests
- Understanding of JSON format
- Basic programming concepts (helpful but not required)

---

## Variables Deep Dive

Variables are Postman's superpower. They make your work reusable, maintainable, and efficient.

### Variable Scopes (Levels)

Postman has **five** variable scopes, from most specific to most general:

```
Global Variables (Available everywhere)
    ↓
Collection Variables (Available in one collection)
    ↓
Environment Variables (Available when environment is active)
    ↓
Data Variables (From CSV/JSON files)
    ↓
Local Variables (Only in scripts)
```

**The Rule:** If two variables have the same name at different scopes, Postman uses the **most specific** one.

**Example:**
```
Local variable: baseUrl = "http://override.com"
Environment variable: baseUrl = "http://localhost:5000"
Global variable: baseUrl = "http://prod.com"

{{baseUrl}} will use: http://override.com (most specific wins)
```

### Global Variables

**When to use:**
- Values needed across ALL collections
- Default settings
- Your user ID for testing

**How to create:**
1. Click the environment dropdown (top right)
2. Select "Globals"
3. Add variables

**Example use case:**
```
Variable: myUserId
Value: 12345

Use in any collection:
GET {{baseUrl}}/users/{{myUserId}}
DELETE {{baseUrl}}/posts/{{postId}}?userId={{myUserId}}
```

### Collection Variables

**When to use:**
- Values specific to one collection
- API keys for a specific service
- Configuration that doesn't change between environments

**How to create:**
1. Click on your collection
2. Go to "Variables" tab
3. Add variables

**Example:**
```
Collection: "Payment API Tests"
Variables:
  merchantId = "merchant_12345"
  apiVersion = "v2"
  
Usage: {{baseUrl}}/{{apiVersion}}/merchants/{{merchantId}}/transactions
Result: http://localhost:5000/v2/merchants/merchant_12345/transactions
```

### Environment Variables

**When to use:**
- Values that change between dev/test/prod
- Configuration per environment

**Best practice:**
Create three environments:
- **Development:** Local testing
- **Staging:** Pre-production testing
- **Production:** Real API (be careful!)

**Example setup:**

**Development Environment:**
```
baseUrl = http://localhost:5000
database = dev_database
adminEmail = admin@dev.local
debug = true
```

**Production Environment:**
```
baseUrl = https://api.production.com
database = prod_database
adminEmail = admin@company.com
debug = false
```

### Dynamic Variables

Postman includes built-in variables that generate random data:

```javascript
{{$guid}}              // Random UUID: 1cd40a1e-c6e4-4f71-9d80-4e2353c06b88
{{$timestamp}}         // Current timestamp: 1641024000
{{$randomInt}}         // Random integer: 42
{{$randomUUID}}        // Random UUID
{{$randomAlphaNumeric}} // Random character: a, 3, x
{{$randomBoolean}}     // Random boolean: true or false
{{$randomIP}}          // Random IP: 192.168.1.1
{{$randomEmail}}       // Random email: user@example.com
{{$randomFullName}}    // Random name: John Smith
{{$randomFirstName}}   // Random first name: John
{{$randomLastName}}    // Random last name: Smith
```

**Example usage:**
```json
POST {{baseUrl}}/api/users
Body:
{
  "username": "user_{{$timestamp}}",
  "email": "{{$randomEmail}}",
  "age": {{$randomInt}},
  "uuid": "{{$guid}}"
}
```

**Why use dynamic variables:**
- Create unique test data
- Avoid conflicts (duplicate usernames)
- Generate realistic data
- Test with variety

### Using Variables in Scripts

**Get a variable:**
```javascript
// Get environment variable
let baseUrl = pm.environment.get("baseUrl");

// Get collection variable
let apiKey = pm.collectionVariables.get("apiKey");

// Get global variable
let userId = pm.globals.get("userId");
```

**Set a variable:**
```javascript
// Set environment variable
pm.environment.set("authToken", "abc123");

// Set collection variable
pm.collectionVariables.set("lastRunTime", new Date());

// Set global variable
pm.globals.set("totalTests", 100);
```

**Remove a variable:**
```javascript
pm.environment.unset("tempToken");
pm.globals.unset("oldData");
```

---

## Pre-request Scripts

Pre-request scripts run **before** your request is sent. They're perfect for:
- Setting up authentication
- Generating dynamic data
- Computing values
- Setting variables from other sources

### Your First Pre-request Script

**Scenario:** Add current timestamp to every request

**Step 1:** Open a request

**Step 2:** Click "Pre-request Script" tab

**Step 3:** Add this code:
```javascript
// Get current timestamp
const currentTimestamp = new Date().toISOString();

// Save to variable
pm.environment.set("currentTime", currentTimestamp);

// Log to console (for debugging)
console.log("Request sent at:", currentTimestamp);
```

**Step 4:** In your request, use `{{currentTime}}` anywhere

**Example:**
```
URL: {{baseUrl}}/api/events?timestamp={{currentTime}}
```

**What happens:**
1. Pre-request script runs
2. Gets current time
3. Saves it to `currentTime` variable
4. Request uses that variable
5. Postman sends request with actual timestamp

### Common Pre-request Script Patterns

#### Pattern 1: Generate Random Test Data

```javascript
// Generate random user data
const randomUser = {
    username: "user_" + pm.variables.replaceIn("{{$timestamp}}"),
    email: pm.variables.replaceIn("{{$randomEmail}}"),
    age: Math.floor(Math.random() * 50) + 18, // Age 18-67
    country: ["USA", "UK", "Canada", "Australia"][Math.floor(Math.random() * 4)]
};

// Save each field
pm.environment.set("testUsername", randomUser.username);
pm.environment.set("testEmail", randomUser.email);
pm.environment.set("testAge", randomUser.age);
pm.environment.set("testCountry", randomUser.country);

console.log("Generated user:", randomUser);
```

**Use in request body:**
```json
{
  "username": "{{testUsername}}",
  "email": "{{testEmail}}",
  "age": {{testAge}},
  "country": "{{testCountry}}"
}
```

#### Pattern 2: Calculate HMAC Signature

Some APIs require cryptographic signatures:

```javascript
// Get values
const apiKey = pm.environment.get("apiKey");
const apiSecret = pm.environment.get("apiSecret");
const timestamp = Date.now().toString();

// Create signature
const message = apiKey + timestamp;
const signature = CryptoJS.HmacSHA256(message, apiSecret).toString();

// Save for request
pm.environment.set("timestamp", timestamp);
pm.environment.set("signature", signature);

console.log("Generated signature for timestamp:", timestamp);
```

**Use in headers:**
```
X-API-Key: {{apiKey}}
X-Timestamp: {{timestamp}}
X-Signature: {{signature}}
```

#### Pattern 3: Refresh Authentication Token

```javascript
// Check if token exists and is valid
const token = pm.environment.get("authToken");
const tokenExpiry = pm.environment.get("tokenExpiry");
const now = Date.now();

if (!token || !tokenExpiry || now > tokenExpiry) {
    console.log("Token expired or missing, refreshing...");
    
    // Send request to get new token
    pm.sendRequest({
        url: pm.environment.get("baseUrl") + "/auth/token",
        method: 'POST',
        header: {
            'Content-Type': 'application/json'
        },
        body: {
            mode: 'raw',
            raw: JSON.stringify({
                client_id: pm.environment.get("clientId"),
                client_secret: pm.environment.get("clientSecret")
            })
        }
    }, function (err, response) {
        if (err) {
            console.error("Failed to refresh token:", err);
            return;
        }
        
        const jsonData = response.json();
        pm.environment.set("authToken", jsonData.access_token);
        // Set expiry to 55 minutes from now (if token lasts 1 hour)
        pm.environment.set("tokenExpiry", now + (55 * 60 * 1000));
        console.log("Token refreshed successfully");
    });
} else {
    console.log("Token still valid");
}
```

---

## Test Scripts

Test scripts run **after** receiving the response. They're used for:
- Verifying response status codes
- Checking response content
- Extracting data for next requests
- Automated assertions

### Your First Test Script

**Scenario:** Verify login was successful

**Step 1:** Send a login request

**Step 2:** Click "Tests" tab

**Step 3:** Add this code:
```javascript
// Test 1: Check status code
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

// Test 2: Check response time
pm.test("Response time is less than 1000ms", function () {
    pm.expect(pm.response.responseTime).to.be.below(1000);
});

// Test 3: Check response has token
pm.test("Response has auth token", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData).to.have.property('token');
});

// Test 4: Save token for future requests
pm.test("Save token to environment", function () {
    const jsonData = pm.response.json();
    pm.environment.set("authToken", jsonData.token);
});
```

**Step 4:** Send the request

**Step 5:** Look at "Test Results" tab in response

You'll see checkmarks (✓) for passed tests or X marks for failed tests.

### Common Test Patterns

#### Pattern 1: Status Code Assertions

```javascript
// Exact status code
pm.test("Status is 200 OK", function () {
    pm.response.to.have.status(200);
});

// Status code in range
pm.test("Status is success (2xx)", function () {
    pm.response.to.be.success; // Any 2xx code
});

// Multiple possible status codes
pm.test("Status is 200 or 201", function () {
    pm.expect(pm.response.code).to.be.oneOf([200, 201]);
});

// Specific status codes for different scenarios
pm.test("Valid response status", function () {
    const status = pm.response.code;
    if (pm.request.method === "POST") {
        pm.expect(status).to.equal(201); // Created
    } else if (pm.request.method === "DELETE") {
        pm.expect(status).to.equal(204); // No Content
    } else {
        pm.expect(status).to.equal(200); // OK
    }
});
```

#### Pattern 2: Response Body Assertions

```javascript
// Parse JSON response
const jsonData = pm.response.json();

// Check property exists
pm.test("Response has 'id' property", function () {
    pm.expect(jsonData).to.have.property('id');
});

// Check property value
pm.test("Username is correct", function () {
    pm.expect(jsonData.username).to.equal("testuser");
});

// Check property type
pm.test("ID is a number", function () {
    pm.expect(jsonData.id).to.be.a('number');
});

// Check array length
pm.test("Returns 10 items", function () {
    pm.expect(jsonData.items).to.have.lengthOf(10);
});

// Check nested properties
pm.test("User email is valid format", function () {
    pm.expect(jsonData.user.email).to.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
});
```

#### Pattern 3: Header Assertions

```javascript
// Check header exists
pm.test("Response has Content-Type header", function () {
    pm.response.to.have.header("Content-Type");
});

// Check header value
pm.test("Content-Type is JSON", function () {
    pm.expect(pm.response.headers.get("Content-Type")).to.include("application/json");
});

// Check CORS headers
pm.test("CORS headers are set", function () {
    pm.expect(pm.response.headers.get("Access-Control-Allow-Origin")).to.exist;
});

// Security headers
pm.test("Security headers present", function () {
    pm.expect(pm.response.headers.get("X-Frame-Options")).to.exist;
    pm.expect(pm.response.headers.get("X-Content-Type-Options")).to.equal("nosniff");
});
```

#### Pattern 4: Response Time Assertions

```javascript
// Maximum response time
pm.test("Response time under 500ms", function () {
    pm.expect(pm.response.responseTime).to.be.below(500);
});

// Different thresholds for different endpoints
pm.test("Response time acceptable", function () {
    const endpoint = pm.request.url.getPath();
    let maxTime;
    
    if (endpoint.includes("/search")) {
        maxTime = 2000; // Search can be slower
    } else if (endpoint.includes("/upload")) {
        maxTime = 5000; // Uploads take longer
    } else {
        maxTime = 1000; // Default
    }
    
    pm.expect(pm.response.responseTime).to.be.below(maxTime);
});
```

### Extracting Data for Next Request

**Scenario:** Login, then use the token in subsequent requests

**Login request Test script:**
```javascript
pm.test("Login successful", function () {
    pm.response.to.have.status(200);
    
    const jsonData = pm.response.json();
    
    // Extract and save token
    pm.environment.set("authToken", jsonData.token);
    
    // Extract and save user ID
    pm.environment.set("currentUserId", jsonData.user.id);
    
    console.log("Saved token and user ID for next requests");
});
```

**Get Profile request (runs after login):**
```
URL: {{baseUrl}}/api/users/{{currentUserId}}
Header: Authorization: Bearer {{authToken}}
```

---

## Authentication Types

Postman supports many authentication methods. Let's explore the most common ones.

### No Auth

No authentication required. For public APIs.

**Example use cases:**
- Public weather APIs
- Open data APIs
- Read-only endpoints

### API Key

Simple authentication using a key in header or query parameter.

**How to set up:**
1. Click "Authorization" tab
2. Select "API Key"
3. Choose where to add key:
   - **Header:** Common (e.g., `X-API-Key`)
   - **Query Params:** Less common
4. Enter key name and value

**Example:**
```
Type: API Key
Key: X-API-Key
Value: your-api-key-123
Add to: Header
```

**Result:** Adds header `X-API-Key: your-api-key-123` to every request

**Pro tip:** Store API key in environment variable:
```
Value: {{apiKey}}
```

### Bearer Token

Used for OAuth 2.0, JWT tokens, etc.

**How to set up:**
1. Authorization → "Bearer Token"
2. Enter token value

**Example:**
```
Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Using variable:**
```
Token: {{authToken}}
```

**Result:** Adds header `Authorization: Bearer <your-token>`

### Basic Auth

Username and password encoded in Base64.

**How to set up:**
1. Authorization → "Basic Auth"
2. Enter username and password

**Example:**
```
Username: admin
Password: secretPass123
```

**Result:** Postman creates header:
```
Authorization: Basic YWRtaW46c2VjcmV0UGFzczEyMw==
```

**Security note:** Basic Auth sends credentials with every request. Only use over HTTPS!

### OAuth 2.0

Complex but secure authentication flow.

**Common for:**
- Google APIs
- Facebook APIs
- GitHub APIs
- Enterprise applications

**How to set up:**
1. Authorization → "OAuth 2.0"
2. Click "Get New Access Token"
3. Fill in details:
   - **Token Name:** Descriptive name
   - **Grant Type:** Usually "Authorization Code"
   - **Callback URL:** Provided by API
   - **Auth URL:** Provided by API
   - **Access Token URL:** Provided by API
   - **Client ID:** From API provider
   - **Client Secret:** From API provider
4. Click "Request Token"
5. Log in when prompted
6. Postman saves token automatically

**Example for GitHub:**
```
Grant Type: Authorization Code
Auth URL: https://github.com/login/oauth/authorize
Access Token URL: https://github.com/login/oauth/access_token
Client ID: your_client_id
Client Secret: your_client_secret
Scope: repo user
```

---

## Chaining Requests

Chaining means using data from one request in subsequent requests.

### Simple Chain Example

**Request 1: Create User**
```
POST {{baseUrl}}/api/users
Body:
{
  "username": "testuser",
  "email": "test@example.com"
}

Tests:
pm.test("User created", function () {
    const jsonData = pm.response.json();
    pm.environment.set("newUserId", jsonData.id);
});
```

**Request 2: Get User Details**
```
GET {{baseUrl}}/api/users/{{newUserId}}

Tests:
pm.test("User retrieved", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData.username).to.equal("testuser");
});
```

**Request 3: Update User**
```
PATCH {{baseUrl}}/api/users/{{newUserId}}
Body:
{
  "email": "updated@example.com"
}
```

**Request 4: Delete User**
```
DELETE {{baseUrl}}/api/users/{{newUserId}}
```

### Complex Chain: E-commerce Flow

**Request 1: Login**
```javascript
// Tests
pm.test("Login successful", function () {
    const jsonData = pm.response.json();
    pm.environment.set("authToken", jsonData.token);
    pm.environment.set("userId", jsonData.user.id);
});
```

**Request 2: Browse Products**
```javascript
// Tests
pm.test("Products loaded", function () {
    const jsonData = pm.response.json();
    // Save first product ID for adding to cart
    pm.environment.set("productId", jsonData.products[0].id);
});
```

**Request 3: Add to Cart**
```javascript
// Request
POST {{baseUrl}}/api/cart
Authorization: Bearer {{authToken}}
Body:
{
  "productId": {{productId}},
  "quantity": 1
}

// Tests
pm.test("Added to cart", function () {
    const jsonData = pm.response.json();
    pm.environment.set("cartId", jsonData.cart.id);
});
```

**Request 4: Checkout**
```javascript
POST {{baseUrl}}/api/checkout
Authorization: Bearer {{authToken}}
Body:
{
  "cartId": {{cartId}},
  "paymentMethod": "credit_card"
}

// Tests
pm.test("Order placed", function () {
    const jsonData = pm.response.json();
    pm.environment.set("orderId", jsonData.order.id);
    pm.environment.set("orderNumber", jsonData.order.orderNumber);
});
```

**Request 5: Track Order**
```javascript
GET {{baseUrl}}/api/orders/{{orderId}}
Authorization: Bearer {{authToken}}

// Tests
pm.test("Order status correct", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData.status).to.equal("confirmed");
});
```

---

## Data-Driven Testing

Test the same endpoint with multiple data sets using CSV or JSON files.

### Using Collection Runner

**Step 1: Prepare Data File**

Create `users.csv`:
```csv
username,email,age,country
john_doe,john@example.com,25,USA
jane_smith,jane@example.com,30,UK
bob_jones,bob@example.com,35,Canada
```

Or `users.json`:
```json
[
  {
    "username": "john_doe",
    "email": "john@example.com",
    "age": 25,
    "country": "USA"
  },
  {
    "username": "jane_smith",
    "email": "jane@example.com",
    "age": 30,
    "country": "UK"
  },
  {
    "username": "bob_jones",
    "email": "bob@example.com",
    "age": 35,
    "country": "Canada"
  }
]
```

**Step 2: Create Request Using Data Variables**

```
POST {{baseUrl}}/api/users
Body:
{
  "username": "{{username}}",
  "email": "{{email}}",
  "age": {{age}},
  "country": "{{country}}"
}

Tests:
pm.test("User created: " + pm.iterationData.get("username"), function () {
    pm.response.to.have.status(201);
});
```

**Step 3: Run with Collection Runner**

1. Click "Collections" in sidebar
2. Click "..." next to your collection
3. Select "Run collection"
4. Click "Select File" next to "Data"
5. Choose your CSV or JSON file
6. Click "Run"

**Result:** Postman runs your request once for each row in the data file!

### Practical Example: Testing Multiple SQL Injection Payloads

**Create `sqli_payloads.csv`:**
```csv
payload,description
' OR '1'='1,Classic OR injection
' OR 1=1--,Comment-based injection
admin'--,Comment out password
' UNION SELECT NULL--,Union-based injection
' AND SLEEP(5)--,Time-based blind injection
```

**Create request:**
```
POST {{baseUrl}}/api/login
Body:
{
  "username": "{{payload}}",
  "password": "anything"
}

Tests:
pm.test("Payload: " + pm.iterationData.get("description"), function () {
    // Should NOT return status 200 (successful login)
    pm.expect(pm.response.code).to.not.equal(200);
    
    // Should return error
    pm.expect(pm.response.code).to.equal(400);
});
```

**Run with Collection Runner:**
- Tests all SQL injection payloads automatically
- Identifies if any succeed (vulnerability!)
- Generates report

---

## Practical Examples

### Example 1: Complete Authentication Flow

**Collection: "User Authentication"**

**Pre-request Script (Collection Level):**
```javascript
// Shared functions available to all requests
pm.collectionVariables.set("timestamp", Date.now());
```

**Request 1: Register**
```javascript
POST {{baseUrl}}/api/register
Body:
{
  "username": "user_{{$timestamp}}",
  "email": "{{$randomEmail}}",
  "password": "TestPass123!"
}

Tests:
pm.test("Registration successful", function () {
    pm.response.to.have.status(201);
    const jsonData = pm.response.json();
    pm.environment.set("testUsername", jsonData.username);
    pm.environment.set("testUserId", jsonData.id);
});
```

**Request 2: Login**
```javascript
POST {{baseUrl}}/api/login
Body:
{
  "username": "{{testUsername}}",
  "password": "TestPass123!"
}

Tests:
pm.test("Login successful", function () {
    pm.response.to.have.status(200);
    const jsonData = pm.response.json();
    pm.environment.set("authToken", jsonData.token);
    
    pm.test("Token is valid JWT", function () {
        const token = jsonData.token;
        const parts = token.split('.');
        pm.expect(parts).to.have.lengthOf(3);
    });
});
```

**Request 3: Access Protected Resource**
```javascript
GET {{baseUrl}}/api/profile
Authorization: Bearer {{authToken}}

Tests:
pm.test("Profile accessed", function () {
    pm.response.to.have.status(200);
    const jsonData = pm.response.json();
    pm.expect(jsonData.id).to.equal(pm.environment.get("testUserId"));
});
```

### Example 2: Error Handling Tests

```javascript
// Collection: "API Error Handling"

// Request: Test 404
GET {{baseUrl}}/api/users/999999

Tests:
pm.test("Returns 404 for non-existent user", function () {
    pm.response.to.have.status(404);
});

pm.test("Error message is clear", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData.error).to.exist;
    pm.expect(jsonData.error).to.include("not found");
});

// Request: Test 401
GET {{baseUrl}}/api/admin/users

Tests:
pm.test("Returns 401 without authentication", function () {
    pm.response.to.have.status(401);
});

// Request: Test 403
GET {{baseUrl}}/api/admin/users
Authorization: Bearer {{regularUserToken}}

Tests:
pm.test("Returns 403 for unauthorized role", function () {
    pm.response.to.have.status(403);
});
```

---

## Summary

You've learned powerful intermediate Postman features:

✓ **Variables** at different scopes (global, collection, environment, local)
✓ **Pre-request scripts** for setup and data generation
✓ **Test scripts** for automated verification
✓ **Authentication** methods (API Key, Bearer, Basic, OAuth)
✓ **Chaining requests** to create complex workflows
✓ **Data-driven testing** with CSV/JSON files

**Next steps:**
1. Practice these concepts with real APIs
2. Move to **04_POSTMAN_ADVANCED.md** for Newman CLI and CI/CD
3. Try **05_AEGISFORGE_INTEGRATION.md** to test real vulnerabilities

**Pro Tips:**
- Start simple, add complexity gradually
- Use console.log() liberally for debugging
- Save your collections regularly
- Document your scripts with comments

Happy automating! 🚀
