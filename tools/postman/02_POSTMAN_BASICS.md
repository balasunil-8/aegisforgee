# Postman Basics - Complete Beginner's Tutorial

## Table of Contents
1. [Introduction](#introduction)
2. [Understanding the Interface](#understanding-the-interface)
3. [Your First Request](#your-first-request)
4. [Understanding HTTP Methods](#understanding-http-methods)
5. [Working with Headers](#working-with-headers)
6. [Request Body and Parameters](#request-body-and-parameters)
7. [Understanding Responses](#understanding-responses)
8. [Creating Collections](#creating-collections)
9. [Using Environments](#using-environments)
10. [Saving and Organizing Work](#saving-and-organizing-work)
11. [Practice Exercises](#practice-exercises)

---

## Introduction

Welcome to Postman Basics! In this guide, we'll walk through everything a beginner needs to know to start using Postman effectively. We'll use simple language and lots of examples.

**By the end of this guide, you'll be able to:**
- Navigate the Postman interface confidently
- Send different types of HTTP requests
- Understand what responses mean
- Organize your work into collections
- Use environments to work efficiently

**Don't worry if you make mistakes!** That's how we learn. Postman is a safe environment where you can experiment freely.

---

## Understanding the Interface

When you first open Postman, you might feel overwhelmed by all the buttons, panels, and options. Let's break it down into digestible pieces.

### The Main Window Layout

Imagine Postman's interface as a workspace divided into distinct areas:

```
┌─────────────────────────────────────────────────────────┐
│  Top Bar: File, Edit, View, Help                       │
├──────────┬──────────────────────────────────────────────┤
│          │  Request Builder Area                        │
│ Sidebar  │  - URL bar and Send button                  │
│          │  - Tabs for different requests               │
│          │  - Request details (headers, body, etc)      │
│          ├──────────────────────────────────────────────┤
│          │  Response Viewer Area                        │
│          │  - Status code and response time             │
│          │  - Response body, headers, cookies           │
└──────────┴──────────────────────────────────────────────┘
```

Let's explore each area in detail.

### The Left Sidebar

**What you see:**
- **Collections:** Folders containing saved requests
- **History:** Recently sent requests
- **APIs:** API documentation (advanced, ignore for now)
- **Environments:** Dropdown to select which environment to use
- **Mock Servers:** For creating fake APIs (advanced)

**What you'll use most:**
- **Collections** - Think of these as folders where you save your work
- **History** - To quickly find and resend previous requests

**How to use it:**

1. **Click on "Collections"** (looks like a folder icon)
   - You'll see any collections you've created
   - Each collection can have folders and requests inside
   - Right-click to create new collections or folders

2. **Click on "History"** (looks like a clock)
   - Shows every request you've sent recently
   - Click any request to load it again
   - Useful if you forgot to save something

**Pro tip:** You can drag requests from History into Collections to save them permanently.

### The Request Builder (Center Area)

This is where the magic happens. This is where you build and send your requests.

**Components from top to bottom:**

#### 1. Tabs Bar
- Just like browser tabs
- Each tab can have a different request
- Click "+" to open a new tab
- Click "x" on a tab to close it

**Why tabs are useful:** You can work on multiple requests without losing your place. For example:
- Tab 1: Testing login
- Tab 2: Testing user profile
- Tab 3: Testing data export

#### 2. Request Name and Save Button
- Shows "Untitled Request" for new requests
- Click to rename
- "Save" button to save to a collection

#### 3. HTTP Method Dropdown and URL Bar

**The dropdown (shows "GET" by default):**
- Click it to see all HTTP methods: GET, POST, PUT, PATCH, DELETE, etc.
- We'll explain each method later

**The URL bar (big text field):**
- Where you type the API endpoint you want to test
- Example: `https://api.example.com/users`

**The Send button (big blue button):**
- Click this to send your request
- Shortcut: Ctrl+Enter (Windows/Linux) or Cmd+Enter (Mac)

#### 4. Request Details Tabs

Below the URL bar, you'll see several tabs:

**Params:**
- For URL parameters (stuff that goes after `?` in URLs)
- Example: `?search=test&page=1`

**Authorization:**
- For API keys, tokens, usernames/passwords
- Postman can handle many authentication types

**Headers:**
- HTTP headers (metadata about your request)
- Example: `Content-Type: application/json`

**Body:**
- For POST/PUT requests where you send data
- Can be JSON, XML, form data, etc.

**Pre-request Script:**
- Advanced: JavaScript code that runs before sending request
- We'll cover this in intermediate guide

**Tests:**
- Advanced: JavaScript code to verify responses
- We'll cover this in intermediate guide

**Settings:**
- Request-specific settings
- Usually can ignore this

**Don't worry about understanding all of these yet.** We'll cover each one with examples.

### The Response Viewer (Bottom Area)

After you send a request, the response appears here.

**Components:**

#### 1. Response Status
Shows three important pieces of info:
- **Status code:** Like `200 OK` or `404 Not Found`
- **Time:** How long the request took (e.g., "523 ms")
- **Size:** How much data was returned (e.g., "1.2 KB")

**Status code colors:**
- **Green (200s):** Success! Everything worked
- **Orange (300s):** Redirection (usually fine)
- **Red (400s):** Client error (you did something wrong)
- **Red (500s):** Server error (the server had a problem)

#### 2. Response Tabs

**Body:**
- The actual content returned by the server
- Can be JSON, HTML, XML, plain text, images, etc.
- Postman formats it nicely for you

**Cookies:**
- Cookies set by the server
- Important for session management

**Headers:**
- HTTP headers sent back by the server
- Shows metadata about the response

**Test Results:**
- If you wrote tests, results appear here
- Green checkmarks = tests passed
- Red X = tests failed

#### 3. Response Display Options

In the Body tab, you'll see view options:

**Pretty:**
- Formatted nicely with colors and indentation
- Best for reading JSON/XML/HTML

**Raw:**
- Exact text as received
- Useful for debugging

**Preview:**
- Renders HTML as a webpage
- Good for testing web pages

**Visualize:**
- Custom visualizations using code
- Advanced feature

---

## Your First Request

Let's send your first request to understand how everything works together!

### Step 1: Open a New Request Tab

1. Click the **"+"** button to open a new tab (or use an existing "Untitled Request" tab)
2. You should see a clean request builder

### Step 2: Choose the HTTP Method

1. Look at the dropdown that says **"GET"**
2. **Leave it as GET** for now
   
**What is GET?** It's the simplest HTTP method. It means "give me information" without changing anything on the server. Like reading a book - you're just looking, not writing.

### Step 3: Enter a URL

In the URL bar, type:
```
https://httpbin.org/get
```

**What is httpbin.org?** It's a free testing service that echoes back whatever you send it. Perfect for learning!

### Step 4: Send the Request

Click the big blue **"Send"** button (or press Ctrl+Enter).

**What happens:**
1. Postman sends a GET request to httpbin.org
2. The server processes it
3. The server sends back a response
4. Postman displays the response

### Step 5: Examine the Response

Look at the response viewer at the bottom. You should see:

**Status:**
```
200 OK        Time: 523 ms        Size: 1.2 KB
```
- **200 OK** means success!
- Time tells you how fast it was
- Size shows how much data came back

**Body (should look similar to this):**
```json
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "PostmanRuntime/7.x.x"
  },
  "origin": "your.ip.address.here",
  "url": "https://httpbin.org/get"
}
```

**What does this response mean?**
- `args`: URL parameters (we didn't send any, so it's empty)
- `headers`: HTTP headers Postman automatically sent
- `origin`: Your IP address
- `url`: The URL you requested

**Congratulations!** You just sent your first API request!

### What Just Happened? (Technical Explanation)

Let's understand what happened behind the scenes:

1. **You clicked Send**
2. **Postman created an HTTP GET request:**
   ```
   GET /get HTTP/1.1
   Host: httpbin.org
   User-Agent: PostmanRuntime/7.x.x
   Accept: */*
   ```

3. **Your computer sent this to httpbin.org's servers**
   - Traveled over the internet
   - Used TCP/IP protocol
   - Encrypted with HTTPS (secure)

4. **httpbin.org's server received the request:**
   - Parsed the request
   - Created a response with your request details
   - Sent it back

5. **Postman received the response and displayed it**

**Why is this important?** Understanding this flow helps you debug problems and test APIs effectively.

---

## Understanding HTTP Methods

HTTP methods (also called HTTP verbs) tell the server what action you want to perform.

### The Most Common Methods

#### GET - "Give me information"

**What it does:** Retrieves data without changing anything.

**Real-world examples:**
- Viewing a user's profile
- Reading blog posts
- Searching for products
- Getting your bank balance

**Example request:**
```
GET https://api.example.com/users/123
```
**Expected response:** Details about user 123

**When to use:** Any time you want to read data without modifying it.

**Security testing with GET:**
- Check if you can access other users' data (IDOR)
- Test for SQL injection in URL parameters
- Look for sensitive data exposure

#### POST - "Create something new"

**What it does:** Sends data to create a new resource.

**Real-world examples:**
- Creating a new user account
- Posting a comment
- Uploading a file
- Submitting a form

**Example request:**
```
POST https://api.example.com/users
Content-Type: application/json

{
  "username": "newuser",
  "email": "user@example.com",
  "password": "Password123!"
}
```
**Expected response:** Details of the newly created user, often with an ID

**When to use:** Creating new resources on the server.

**Security testing with POST:**
- Test for SQL injection in form fields
- Try XSS payloads in text fields
- Check password requirements
- Test for mass assignment vulnerabilities

#### PUT - "Replace this entirely"

**What it does:** Replaces an entire resource with new data.

**Real-world examples:**
- Updating your entire user profile
- Replacing a document
- Changing all settings at once

**Example request:**
```
PUT https://api.example.com/users/123
Content-Type: application/json

{
  "username": "updateduser",
  "email": "updated@example.com",
  "password": "NewPassword123!"
}
```

**Note:** PUT replaces **everything**. If you don't include a field, it might be deleted or set to default.

**When to use:** When you want to completely replace a resource.

#### PATCH - "Update just these parts"

**What it does:** Updates only specific fields of a resource.

**Real-world examples:**
- Changing just your email address
- Updating just your password
- Modifying one setting

**Example request:**
```
PATCH https://api.example.com/users/123
Content-Type: application/json

{
  "email": "newemail@example.com"
}
```

**Note:** PATCH only changes the fields you specify. Other fields stay the same.

**When to use:** When you want to update specific fields without affecting others.

**Security testing with PATCH:**
- Try to modify fields you shouldn't (like `is_admin`)
- Test if you can update other users' data
- Check for parameter tampering

#### DELETE - "Remove this"

**What it does:** Deletes a resource.

**Real-world examples:**
- Deleting your account
- Removing a post
- Clearing a shopping cart

**Example request:**
```
DELETE https://api.example.com/users/123
```

**Expected response:** Often just a status code (like 204 No Content) or a confirmation message

**When to use:** When you want to remove something from the server.

**Security testing with DELETE:**
- Check if you can delete other users' data
- Test if deleted data can be recovered
- Verify proper authorization

### Less Common Methods (Good to Know)

**HEAD:** Like GET, but only returns headers (no body)
**OPTIONS:** Asks the server what methods are allowed
**CONNECT:** Used for proxying (rare)
**TRACE:** Debugging method (often disabled for security)

---

## Working with Headers

Headers are like envelopes for your requests and responses. They contain important metadata.

### What Are Headers?

Headers are key-value pairs that provide additional information about the request or response.

**Format:**
```
Header-Name: Header-Value
```

**Example headers:**
```
Content-Type: application/json
Authorization: Bearer your-token-here
User-Agent: PostmanRuntime/7.x.x
Accept: application/json
```

### Viewing Headers in Postman

**Request headers:**
1. In the request builder, click the **"Headers"** tab
2. You'll see a table with Key and Value columns
3. Some headers are added automatically (shown in gray/light text)

**Response headers:**
1. After sending a request, look at the response area
2. Click the **"Headers"** tab (next to Body)
3. You'll see all headers the server sent back

### Common Request Headers

#### Content-Type
**What it does:** Tells the server what format your data is in.

**Common values:**
- `application/json` - JSON data
- `application/x-www-form-urlencoded` - Form data
- `multipart/form-data` - File uploads
- `text/html` - HTML content
- `text/plain` - Plain text

**Example usage:**
```
POST https://api.example.com/users
Content-Type: application/json

{"username": "testuser"}
```

**Why it matters:** If you send JSON but specify `text/html`, the server might reject your request or parse it wrong.

#### Authorization
**What it does:** Proves you have permission to access the API.

**Common types:**
- `Bearer <token>` - JWT or OAuth tokens
- `Basic <base64-encoded-credentials>` - Username:password
- `API-Key <key>` - Simple API key

**Example:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Security note:** Never share your authorization tokens publicly!

#### Accept
**What it does:** Tells the server what response format you prefer.

**Example:**
```
Accept: application/json
```

This tells the server: "Please send me JSON data back."

#### User-Agent
**What it does:** Identifies what software is making the request.

**Postman's default:**
```
User-Agent: PostmanRuntime/7.x.x
```

**Why it matters:** Some APIs behave differently based on User-Agent (though they shouldn't for security reasons!).

### Adding Custom Headers in Postman

**Step 1:** Click the **"Headers"** tab under the URL bar

**Step 2:** Click in the "Key" column and type your header name

**Step 3:** Click in the "Value" column and type your header value

**Step 4:** Click the checkbox to enable/disable the header

**Example: Adding an API Key**
```
Key: X-API-Key
Value: your-api-key-here
```

**Pro tip:** Use the checkbox to temporarily disable headers without deleting them. Great for testing!

---

## Request Body and Parameters

### URL Parameters (Query Strings)

Parameters that appear in the URL after a `?` symbol.

**Format:**
```
https://api.example.com/search?query=test&page=1&limit=10
```

**Breaking it down:**
- `?` - Starts the query string
- `query=test` - First parameter
- `&` - Separates parameters
- `page=1` - Second parameter
- `limit=10` - Third parameter

**In Postman:**

1. Click the **"Params"** tab
2. You'll see a table with Key and Value columns
3. Add parameters without worrying about formatting

**Example:**
```
Key         Value
query       test
page        1
limit       10
```

Postman automatically creates: `?query=test&page=1&limit=10`

**Why use Params tab instead of typing in URL?**
- Easier to read and edit
- Can enable/disable parameters with checkboxes
- Postman handles encoding special characters

### Request Body

For POST, PUT, and PATCH requests, you usually send data in the request body.

**In Postman:**

1. Click the **"Body"** tab
2. Choose a data format:

#### none
No body at all. Used for GET, DELETE, or simple requests.

#### form-data
Like filling out a web form. Can include files.

**Use for:** File uploads, traditional form submissions

**Example:**
```
Key           Value
username      testuser
email         test@example.com
avatar        [Select File button]
```

#### x-www-form-urlencoded
Like form-data but URL-encoded. Cannot include files.

**Use for:** Simple form submissions, legacy APIs

**Example:**
```
Key           Value
username      testuser
password      Password123!
```

#### raw
Send raw text data. You specify the format.

**Use for:** JSON, XML, plain text

**Example (JSON):**
```json
{
  "username": "testuser",
  "email": "test@example.com",
  "password": "Password123!"
}
```

**Important:** When using raw JSON:
1. Select "raw" option
2. Choose "JSON" from the dropdown (right side)
3. Postman automatically adds `Content-Type: application/json` header

#### binary
Upload a single file as the entire request body.

**Use for:** Image uploads, document uploads

#### GraphQL
Special format for GraphQL APIs (advanced).

---

## Understanding Responses

After sending a request, understanding the response is crucial.

### HTTP Status Codes

Status codes tell you what happened with your request.

#### 2xx Success
**200 OK:**
- Everything worked perfectly
- Most common success status

**201 Created:**
- Resource successfully created
- Common after POST requests

**204 No Content:**
- Success, but no data to return
- Common after DELETE requests

#### 3xx Redirection
**301 Moved Permanently:**
- Resource moved to new URL
- Browser/Postman should use new URL from now on

**302 Found (Temporary Redirect):**
- Resource temporarily at different URL
- Use original URL next time

#### 4xx Client Errors
**400 Bad Request:**
- You sent malformed data
- Check your request format

**401 Unauthorized:**
- Authentication required or failed
- Check your credentials

**403 Forbidden:**
- You're authenticated but don't have permission
- Check authorization

**404 Not Found:**
- Resource doesn't exist
- Check the URL

**429 Too Many Requests:**
- You're sending requests too fast
- Wait and try again

#### 5xx Server Errors
**500 Internal Server Error:**
- Something broke on the server
- Often a bug in the server code
- **In security testing:** Might indicate successful injection!

**502 Bad Gateway:**
- Server got invalid response from another server
- Usually temporary

**503 Service Unavailable:**
- Server overloaded or down for maintenance
- Try again later

### Response Body Formats

#### JSON (Most Common)

**Looks like:**
```json
{
  "id": 123,
  "username": "testuser",
  "email": "test@example.com",
  "created_at": "2024-01-15T10:30:00Z"
}
```

**In Postman:**
- Automatically formatted with syntax highlighting
- Can collapse/expand sections
- Click "Pretty" tab for formatted view

#### XML

**Looks like:**
```xml
<user>
  <id>123</id>
  <username>testuser</username>
  <email>test@example.com</email>
</user>
```

#### HTML

**Looks like:**
```html
<!DOCTYPE html>
<html>
<head><title>Page Title</title></head>
<body>
  <h1>Welcome</h1>
  <p>Content here</p>
</body>
</html>
```

**In Postman:** Click "Preview" tab to see rendered webpage

#### Plain Text

Just regular text without special formatting.

---

## Creating Collections

Collections are how you organize and save your work in Postman.

### What Is a Collection?

Think of a collection as a folder that contains:
- Related API requests
- Folders for organization
- Shared settings and variables

**Example collection structure:**
```
User Management API
├── Authentication
│   ├── Login
│   └── Logout
├── Users
│   ├── Get All Users
│   ├── Get User by ID
│   ├── Create User
│   ├── Update User
│   └── Delete User
└── Settings
    ├── Get Settings
    └── Update Settings
```

### Creating Your First Collection

**Step 1:** Click "Collections" in the left sidebar

**Step 2:** Click the "+" or "Create a collection" button

**Step 3:** Name your collection (e.g., "My First API Tests")

**Step 4:** (Optional) Add a description

**Step 5:** Click "Create"

### Adding Requests to Collections

**Method 1: Save a New Request**
1. Create a request in a tab
2. Click "Save" button (next to Send)
3. Choose which collection to save to
4. Name the request
5. Click "Save"

**Method 2: Drag from History**
1. Click "History" in left sidebar
2. Find a request you sent earlier
3. Drag it to a collection in the sidebar

### Organizing with Folders

Collections can have folders for better organization.

**To create a folder:**
1. Right-click on a collection
2. Select "Add folder"
3. Name the folder
4. Click "Create"

**To move requests into folders:**
- Drag and drop requests into folders

**Example organization:**
```
E-Commerce API
├── Products
│   ├── List Products
│   ├── Get Product Details
│   └── Search Products
├── Cart
│   ├── Add to Cart
│   ├── View Cart
│   └── Checkout
└── Orders
    ├── Place Order
    └── Track Order
```

---

## Using Environments

Environments help you switch between different setups (development, testing, production) without changing your requests.

### What Is an Environment?

An environment is a set of variables. Think of it like this:

**Without environments:**
```
Request 1: https://dev.example.com/api/users
Request 2: https://dev.example.com/api/products
Request 3: https://dev.example.com/api/orders

When moving to production, you must manually change:
Request 1: https://prod.example.com/api/users
Request 2: https://prod.example.com/api/products
Request 3: https://prod.example.com/api/orders
```

**With environments:**
```
Request 1: {{baseUrl}}/api/users
Request 2: {{baseUrl}}/api/products  
Request 3: {{baseUrl}}/api/orders

Development environment: baseUrl = https://dev.example.com
Production environment: baseUrl = https://prod.example.com
```

Just switch environments, and all requests automatically use the right URL!

### Creating an Environment

**Step 1:** Click the environment dropdown (top right, says "No Environment")

**Step 2:** Click "Create new environment" or the "+" icon

**Step 3:** Name your environment (e.g., "Development")

**Step 4:** Add variables:

**Example:**
```
Variable        Initial Value              Current Value
baseUrl         http://localhost:5000      http://localhost:5000
apiKey          dev-api-key-123            dev-api-key-123
username        testuser                   testuser
```

**Step 5:** Click "Save"

### Using Environment Variables

In any request field, use `{{variableName}}` syntax:

**Example:**
```
URL: {{baseUrl}}/api/users
Header: Authorization: {{apiKey}}
```

When you send the request, Postman automatically replaces `{{baseUrl}}` with the actual value from your active environment.

### Switching Environments

Click the environment dropdown and select a different environment. All your requests immediately use the new environment's values.

**Common setup:**
- **Development:** `baseUrl = http://localhost:5000`
- **Testing:** `baseUrl = https://test.example.com`
- **Production:** `baseUrl = https://api.example.com`

---

## Saving and Organizing Work

### Why Save Your Work?

- **Reproducibility:** Run the same test again tomorrow
- **Collaboration:** Share with teammates
- **Documentation:** Show others how the API works
- **Efficiency:** Don't recreate requests from scratch

### Best Practices for Organization

#### 1. Use Descriptive Names

**Bad:**
- Request 1
- Test
- API Call

**Good:**
- Login with Valid Credentials
- Get User Profile by ID
- Create New Product (Admin)

#### 2. Organize by Feature

Group related requests together:
```
User Management
├── Authentication
│   ├── Login
│   ├── Logout
│   └── Refresh Token
├── User Profile
│   ├── Get Current User
│   ├── Update Profile
│   └── Upload Avatar
└── User Administration (Admin Only)
    ├── List All Users
    ├── Ban User
    └── Delete User
```

#### 3. Add Descriptions

Click the documentation icon next to any request or collection to add:
- What the endpoint does
- Required parameters
- Expected responses
- Example usage

#### 4. Use Consistent Naming

Choose a pattern and stick to it:
- **HTTP Method First:** "GET User Profile", "POST Create User"
- **Action First:** "Login User", "Fetch Products"
- **Resource First:** "User - Login", "Product - Create"

---

## Practice Exercises

Let's put everything together with hands-on exercises!

### Exercise 1: Basic GET Request

**Goal:** Retrieve user information

**Instructions:**
1. Open a new tab
2. Set method to GET
3. URL: `https://jsonplaceholder.typicode.com/users/1`
4. Click Send

**Expected Result:**
- Status: 200 OK
- Body: JSON object with user details

**What you learned:**
- How to send GET requests
- Reading JSON responses

### Exercise 2: POST Request with JSON Body

**Goal:** Create a new post

**Instructions:**
1. New tab
2. Set method to POST
3. URL: `https://jsonplaceholder.typicode.com/posts`
4. Click "Body" tab
5. Select "raw" and "JSON"
6. Enter:
```json
{
  "title": "My First Post",
  "body": "This is my test post",
  "userId": 1
}
```
7. Click Send

**Expected Result:**
- Status: 201 Created
- Body: Your post with an ID assigned

**What you learned:**
- Sending POST requests
- Including JSON data
- Creating resources

### Exercise 3: Using URL Parameters

**Goal:** Search for posts by user

**Instructions:**
1. New tab
2. Method: GET
3. URL: `https://jsonplaceholder.typicode.com/posts`
4. Click "Params" tab
5. Add parameter:
   - Key: `userId`
   - Value: `1`
6. Click Send

**Expected Result:**
- Status: 200 OK
- Body: Array of posts from user 1

**What you learned:**
- Adding URL parameters
- Filtering results

### Exercise 4: Create a Collection

**Goal:** Save and organize your requests

**Instructions:**
1. Create a new collection named "API Practice"
2. Create two folders:
   - "Users"
   - "Posts"
3. Save Exercise 1 to "Users" folder
4. Save Exercises 2 and 3 to "Posts" folder
5. Add descriptions to each request

**What you learned:**
- Creating collections
- Organizing with folders
- Documenting your work

### Exercise 5: Using Environments

**Goal:** Use variables for the base URL

**Instructions:**
1. Create environment named "JSONPlaceholder"
2. Add variable:
   - Variable: `baseUrl`
   - Value: `https://jsonplaceholder.typicode.com`
3. Select this environment
4. Create new request:
   - Method: GET
   - URL: `{{baseUrl}}/users`
5. Send request

**Expected Result:**
- Status: 200 OK
- Body: Array of users
- Postman replaced `{{baseUrl}}` with actual URL

**What you learned:**
- Creating environments
- Using variables
- Making requests flexible

---

## Summary

**Congratulations!** You've completed Postman Basics. You now know:

✓ How to navigate the Postman interface
✓ How to send GET and POST requests
✓ What HTTP methods are and when to use them
✓ How to work with headers and request bodies
✓ How to understand status codes and responses
✓ How to create and organize collections
✓ How to use environments and variables

**Next Steps:**

1. **Practice regularly** - The more you use Postman, the more comfortable you'll become
2. **Move to 03_POSTMAN_INTERMEDIATE.md** - Learn variables, scripting, and automation
3. **Try 05_AEGISFORGE_INTEGRATION.md** - Start testing real vulnerabilities

**Remember:**
- Postman is a tool for exploration and learning
- Making mistakes is part of the process
- Start simple, then gradually use more advanced features
- The interface might seem complex at first, but you'll develop muscle memory

**You're ready to move forward!** When you feel comfortable with these basics, proceed to the Intermediate guide where we'll cover scripting, automated testing, and more advanced techniques.

Happy testing! 🚀
