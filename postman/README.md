# AegisForge Complete Postman Collection

## 📋 Overview

This is a comprehensive Postman collection with **141+ API requests** designed for security testing and learning. The collection includes both vulnerable (RED TEAM) and secure (BLUE TEAM) implementations of common web application vulnerabilities.

## 📊 Collection Statistics

- **Total Requests**: 141
- **RED TEAM**: 87 vulnerable endpoints
- **BLUE TEAM**: 54 secure endpoints
- **Schema**: Postman Collection v2.1.0
- **File Size**: ~142 KB

## 🚀 Quick Start

### 1. Import Collection

1. Open Postman
2. Click **Import** button
3. Select `AegisForge_Complete_Collection.json`
4. Click **Import**

### 2. Configure Environment Variables

The collection uses the following variables:

| Variable | Default Value | Description |
|----------|---------------|-------------|
| `red_base_url` | `http://localhost:5000` | RED TEAM vulnerable endpoints |
| `blue_base_url` | `http://localhost:5001` | BLUE TEAM secure endpoints |
| `access_token` | *(empty)* | JWT token (auto-populated after login) |
| `user_id` | `1` | Current user ID (auto-populated) |
| `csrf_token` | *(empty)* | CSRF token for protected endpoints |
| `admin_token` | *(empty)* | Admin JWT token (auto-populated) |

### 3. Start Testing

1. **Start RED TEAM server** (port 5000)
2. **Start BLUE TEAM server** (port 5001)
3. Run authentication requests first to populate tokens
4. Execute other requests in any order

## 🔴 RED TEAM - Vulnerable Endpoints (Port 5000)

### Categories

#### 01 - Authentication (10 requests)
- User registration
- User login
- Weak password acceptance
- Brute force attacks (5 attempts)
- Admin login
- Profile access

#### 02 - SQL Injection (12 requests)
- Boolean-based SQLi
- Time-based blind SQLi
- Union-based SQLi
- Authentication bypass
- Database enumeration
- Column extraction
- Stacked queries

#### 03 - Cross-Site Scripting (10 requests)
- Reflected XSS (GET parameters, URL path)
- Stored XSS (comments, profiles)
- DOM-based XSS
- Event handler injection
- SVG vector attacks
- JavaScript protocol

#### 04 - Access Control & IDOR (11 requests)
- Access own resources
- IDOR - access other users
- IDOR - modify other users
- IDOR - delete users
- Access other user orders
- Privilege escalation
- Admin panel access
- Missing function-level access control

#### 05 - Command Injection (7 requests)
- OS command injection via ping
- DNS lookup injection
- Pipe operator injection
- AND operator injection
- Backtick injection
- File read via command injection

#### 06 - XML External Entity (4 requests)
- Basic XXE
- Parameter entity XXE
- Blind XXE
- Internal file disclosure

#### 07 - Server-Side Request Forgery (7 requests)
- Internal network scanning
- Localhost access
- Internal IP access
- Cloud metadata access
- File protocol SSRF
- Webhook SSRF
- DNS rebinding

#### 08 - Open Redirect (5 requests)
- External site redirect
- JavaScript protocol
- Data URI
- Double slash bypass
- URL encoding

#### 09 - Business Logic Flaws (7 requests)
- Race conditions
- Negative amounts
- Price manipulation
- Coupon reuse
- Integer overflow
- Parameter tampering

#### 10 - Information Disclosure (10 requests)
- Verbose error messages
- Path traversal attacks
- Configuration exposure
- Debug endpoints
- Server info disclosure
- Git directory exposure
- Backup file exposure
- Environment variable leaks

#### 11 - Utility & Information (4 requests)
- Health check
- Vulnerability list
- API documentation
- Server status

## 🔵 BLUE TEAM - Secure Endpoints (Port 5001)

### Categories

#### 01 - Authentication (Secure) (8 requests)
- Secure registration with password validation
- Weak password rejection
- Secure login
- Rate limiting demonstration
- Failed login attempts
- Profile access with authentication

#### 02 - SQL Injection Prevention (5 requests)
- Parameterized queries
- SQLi attempt blocking (boolean, union, search, login)

#### 03 - XSS Prevention (5 requests)
- Input sanitization
- Output encoding
- Script tag blocking
- Event handler blocking
- SVG sanitization

#### 04 - Access Control (Secure) (6 requests)
- Proper authorization checks
- IDOR prevention
- Update/delete protection
- Privilege escalation prevention
- Admin panel protection

#### 05 - Command Injection Prevention (4 requests)
- Input validation
- Command sanitization
- Pipe/AND operator blocking

#### 06 - XXE Prevention (2 requests)
- Safe XML parsing
- External entity blocking

#### 07 - SSRF Prevention (5 requests)
- URL whitelist validation
- Localhost blocking
- Internal IP blocking
- Cloud metadata protection
- File protocol blocking

#### 08 - Open Redirect Prevention (3 requests)
- Internal redirect only
- External URL blocking
- JavaScript protocol blocking

#### 09 - Business Logic (Secure) (4 requests)
- Proper validation
- Negative amount rejection
- Price tampering prevention
- Valid order processing

#### 10 - Information Disclosure Prevention (4 requests)
- Generic error messages
- Path traversal blocking
- Config endpoint protection
- Debug endpoint disabled

#### 11 - CSRF Protection (3 requests)
- CSRF token generation
- Token validation
- Protected state-changing operations

#### 12 - File Upload (Secure) (2 requests)
- Valid file upload
- Malicious file blocking

#### 13 - Utility & Information (3 requests)
- Health check
- API status
- Documentation

## 🎯 Usage Patterns

### Testing Workflow

1. **Authentication Flow**
   ```
   RED TEAM:
   1. Register User → 2. Login User → 3. Access Protected Resources
   
   BLUE TEAM:
   1. Register User → 2. Login User → 3. Get CSRF Token → 4. Access Protected Resources
   ```

2. **Vulnerability Testing**
   ```
   For each vulnerability type:
   1. Run RED TEAM request to see vulnerability
   2. Run equivalent BLUE TEAM request to see protection
   3. Compare responses and behavior
   ```

3. **Automated Testing**
   - Use Postman Collection Runner
   - Select folder to test
   - Review test results
   - Export results for reporting

### Test Scripts

Each request includes:
- **Status code validation**
- **Response structure validation**
- **Vulnerability detection checks**
- **Auto-variable population** (tokens, IDs)

Example test script:
```javascript
pm.test('Status code is 200', function () {
    pm.response.to.have.status(200);
});

pm.test('Response has access_token', function () {
    var jsonData = pm.response.json();
    pm.expect(jsonData).to.have.property('access_token');
    pm.collectionVariables.set('access_token', jsonData.access_token);
});
```

## 🔧 Advanced Features

### Environment Setup

Create separate environments for different testing scenarios:

```json
{
  "red_base_url": "http://localhost:5000",
  "blue_base_url": "http://localhost:5001",
  "test_user_email": "test@example.com",
  "test_user_password": "TestPassword123!"
}
```

### Pre-request Scripts

Some requests automatically:
- Retrieve authentication tokens
- Set CSRF tokens
- Update user IDs

### Response Validation

Test scripts validate:
- HTTP status codes
- JSON structure
- Security headers
- Error messages
- Data integrity

## 📚 Educational Use

### Learning Path

1. **Beginners**: Start with Authentication and XSS
2. **Intermediate**: Progress to SQLi and IDOR
3. **Advanced**: Tackle XXE, SSRF, and Business Logic

### Best Practices

- Always run RED TEAM first to understand the vulnerability
- Compare with BLUE TEAM to see proper defenses
- Review test scripts to understand detection methods
- Use Collection Runner for comprehensive testing
- Document findings and remediation steps

## 🛡️ Security Notes

⚠️ **WARNING**: RED TEAM endpoints are intentionally vulnerable!

- **Never deploy RED TEAM endpoints to production**
- Use only in isolated testing environments
- Do not test against systems you don't own
- Follow responsible disclosure practices
- Use for educational purposes only

## 📝 Documentation

### Request Format

All requests follow this structure:

```json
{
  "name": "Request Name",
  "event": [/* Test scripts */],
  "request": {
    "method": "GET|POST|PUT|DELETE",
    "header": [/* Headers */],
    "body": {/* Request body */},
    "url": {
      "raw": "{{base_url}}/path",
      "host": ["{{base_url}}"],
      "path": ["api", "endpoint"]
    }
  }
}
```

### Response Handling

Responses are validated using:
- Status code checks
- JSON structure validation
- Security header verification
- Error message analysis

## 🤝 Contributing

To add new requests:

1. Use the `create_request()` helper function
2. Include proper test scripts
3. Add to appropriate category
4. Update documentation
5. Test both RED and BLUE variants

## 📄 License

Part of the AegisForge Security Platform.

## 🔗 Related Resources

- [AegisForge Documentation](../README.md)
- [Security Testing Guide](../PENTESTLAB_TESTING_GUIDE.md)
- [API Documentation](../API_DOCUMENTATION.md)
- [Deployment Guide](../DEPLOYMENT_GUIDE.md)

---

**Last Updated**: 2024
**Collection Version**: 2.1.0
**Total Requests**: 141
