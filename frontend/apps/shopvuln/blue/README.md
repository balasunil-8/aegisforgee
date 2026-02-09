# ShopVuln Blue Team (SECURE) Version

## Overview

This directory contains the **secure Blue Team version** of the ShopVuln e-commerce application. These HTML pages implement comprehensive security controls to defend against common web vulnerabilities found in the Red Team version.

## 🛡️ Security Improvements Implemented

### 1. **Cross-Site Scripting (XSS) Prevention**

#### Content Security Policy (CSP)
All pages include a strict Content Security Policy that:
- Restricts script sources to `self` and nonce-based inline scripts
- Prevents execution of untrusted scripts
- Limits external resources to trusted CDNs
- Blocks unsafe inline scripts without proper nonces

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'nonce-{{NONCE}}'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' https: data:; connect-src 'self' /api/blue/shopvuln/">
```

#### Input/Output Sanitization
- All user inputs are validated with HTML5 patterns
- Search queries limited to alphanumeric characters and safe symbols
- Product data sanitized before rendering
- Review submissions validated and escaped

### 2. **Cross-Site Request Forgery (CSRF) Protection**

All forms include CSRF tokens:
```html
<input type="hidden" name="csrf_token" value="{{CSRF_TOKEN}}">
```

Protected forms include:
- Search forms
- Newsletter subscriptions
- Checkout forms
- Review submissions
- Coupon redemption
- Order operations

### 3. **Input Validation**

#### Client-Side Validation
All input fields include appropriate validation attributes:

**Email Validation:**
```html
<input type="email" pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$" maxlength="100" required>
```

**Search Input:**
```html
<input type="text" pattern="[a-zA-Z0-9\s\-]+" maxlength="100" required>
```

**Numeric Fields:**
```html
<input type="number" min="0" max="99999" step="0.01" required>
```

**Credit Card Fields:**
```html
<input type="text" maxlength="19" pattern="\d{4}\s?\d{4}\s?\d{4}\s?\d{4}" required>
```

### 4. **Security Headers**

All pages include essential security headers:

```html
<!-- Prevent MIME type sniffing -->
<meta http-equiv="X-Content-Type-Options" content="nosniff">

<!-- Prevent clickjacking -->
<meta http-equiv="X-Frame-Options" content="DENY">

<!-- Enable XSS filter -->
<meta http-equiv="X-XSS-Protection" content="1; mode=block">

<!-- Control referrer information -->
<meta name="referrer" content="strict-origin-when-cross-origin">
```

### 5. **SQL Injection Prevention**

- All database queries use parameterized statements (server-side)
- Category filters validated against whitelist
- Sort parameters validated
- Order IDs validated for proper format

### 6. **Insecure Direct Object Reference (IDOR) Protection**

- Order access requires authentication
- Product IDs validated with authorization checks
- User-specific data verified server-side
- Order details require valid session

### 7. **Rate Limiting & Brute Force Protection**

- Coupon validation rate-limited (server-side)
- Login attempts tracked and limited
- Password reset requests throttled
- API calls rate-limited

### 8. **Secure Session Management**

- Session tokens generated with cryptographically secure randomness
- Session IDs rotated on authentication
- Secure and HttpOnly flags set on cookies
- Session timeout implemented

### 9. **Payment Card Industry (PCI) Compliance**

- Card data never stored in localStorage
- HTTPS enforced for all transactions
- Sensitive data encrypted in transit
- CVV never logged or stored

### 10. **Secure API Endpoints**

All API calls directed to secure endpoints:
- Changed from: `/api/red/shopvuln/`
- Changed to: `/api/blue/shopvuln/`

The Blue Team API implements:
- Authentication and authorization
- Input validation
- Output encoding
- Rate limiting
- Error handling without information disclosure

## 📄 Secure Pages

### 1. **index.html** - Homepage
- Secure search with input validation
- Sanitized product displays
- Protected newsletter signup
- CSRF-protected forms

### 2. **search.html** - Product Search
- XSS-safe search query display
- Validated filter parameters
- Sanitized product results
- Secure pagination

### 3. **product.html** - Product Details
- Protected review submissions
- Sanitized user-generated content
- Validated quantity inputs
- Secure add-to-cart functionality

### 4. **cart.html** - Shopping Cart
- Server-side quantity validation
- Protected coupon application
- Secure price calculations
- Validated cart operations

### 5. **checkout.html** - Checkout Process
- CSRF-protected payment forms
- Validated shipping information
- Secure payment processing
- Protected order submission

### 6. **orders.html** - Order History
- Authorization-based order access
- Protected order details
- Secure invoice generation
- Validated order operations

### 7. **coupon.html** - Coupons & Deals
- Rate-limited coupon validation
- Protected coupon generation
- Secure coupon application
- Validated redemption

## 🔒 Additional Security Features

### Nonce-Based Script Execution
All inline scripts use cryptographic nonces:
```html
<script nonce="{{NONCE}}" src="js/main.js"></script>
```

### Secure Random Token Generation
- CSRF tokens: 256-bit cryptographically secure random
- Session IDs: 128-bit secure random
- Nonces: 128-bit per-request random

### Error Handling
- Generic error messages (no information disclosure)
- Detailed errors logged server-side only
- User-friendly fallback messages

### Logging & Monitoring
- Security events logged
- Failed authentication attempts tracked
- Suspicious activity flagged
- Audit trail maintained

## 🎯 Vulnerability Remediation Summary

| Vulnerability | Red Team | Blue Team |
|--------------|----------|-----------|
| **XSS** | ❌ User input reflected without encoding | ✅ CSP + input validation + output encoding |
| **CSRF** | ❌ No CSRF tokens | ✅ CSRF tokens on all forms |
| **SQL Injection** | ❌ Direct SQL queries | ✅ Parameterized queries + validation |
| **IDOR** | ❌ Predictable IDs, no auth check | ✅ Authorization checks + random IDs |
| **Session Fixation** | ❌ Session ID not rotated | ✅ Session rotation + secure flags |
| **Information Disclosure** | ❌ Verbose errors exposed | ✅ Generic errors + server logging |
| **Broken Access Control** | ❌ Missing authorization | ✅ Proper access controls |
| **Security Misconfiguration** | ❌ Missing security headers | ✅ Complete security headers |
| **Sensitive Data Exposure** | ❌ PCI data in localStorage | ✅ Never store sensitive data |
| **Insufficient Logging** | ❌ No security logging | ✅ Comprehensive audit logs |

## 🚀 Usage

### For Training & Education
1. Compare Red Team vs Blue Team implementations
2. Identify security controls added
3. Understand defense-in-depth approach
4. Practice secure coding patterns

### For Testing
1. Attempt exploits that work on Red Team
2. Observe security controls blocking attacks
3. Test input validation
4. Verify CSRF protection

### For Development
1. Use as reference for secure implementations
2. Copy security patterns to your projects
3. Adapt security controls to your needs
4. Follow secure coding guidelines

## 📚 Best Practices Demonstrated

1. **Defense in Depth**: Multiple layers of security controls
2. **Principle of Least Privilege**: Minimal access granted
3. **Secure by Default**: Security built-in from the start
4. **Fail Securely**: Errors don't compromise security
5. **Don't Trust User Input**: All input validated and sanitized
6. **Complete Mediation**: Every request authorized
7. **Open Design**: Security through proper implementation, not obscurity
8. **Separation of Duties**: Client and server validation
9. **Least Common Mechanism**: Shared resources minimized
10. **Psychological Acceptability**: Security doesn't hinder usability

## 🔍 Testing the Security

### XSS Testing
Try injecting scripts in:
- Search box: `<script>alert('XSS')</script>`
- Product reviews: `<img src=x onerror=alert('XSS')>`
- Order notes: `<svg onload=alert('XSS')>`

**Expected Result**: CSP blocks execution, input validation rejects malicious input

### CSRF Testing
Try submitting forms without CSRF token:
- Coupon application
- Order placement
- Review submission

**Expected Result**: Request rejected due to missing/invalid CSRF token

### SQL Injection Testing
Try SQL injection in:
- Search: `' OR '1'='1`
- Category filter: `electronics' OR '1'='1`
- Sort parameter: `price; DROP TABLE products;--`

**Expected Result**: Input validation rejects, parameterized queries prevent injection

### IDOR Testing
Try accessing other users' data:
- Order details: `/orders.html?order_id=10235`
- User profiles: `/profile.html?user_id=999`

**Expected Result**: Authorization check denies access

## 📖 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Content Security Policy Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

## 🛠️ Technical Stack

- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Security**: CSP, CSRF tokens, Input validation
- **API**: RESTful with `/api/blue/shopvuln/` endpoints
- **Session**: Secure HTTP-only cookies
- **Encryption**: TLS 1.3 for all connections

## 📝 Notes

- These pages require a secure backend implementation to function properly
- CSRF tokens and nonces must be generated server-side
- All security controls work together (defense in depth)
- Regular security audits and updates recommended
- Monitor logs for security events

## 🎓 Educational Value

This Blue Team implementation demonstrates:
- How to fix common web vulnerabilities
- Proper implementation of security controls
- Defense-in-depth security architecture
- Secure coding best practices
- Real-world security patterns

Compare with the Red Team version to understand:
- What makes code vulnerable
- How attackers exploit weaknesses
- How to defend against attacks
- Why security controls are necessary

## ⚠️ Disclaimer

This is an educational application designed to teach web security. While it implements many security best practices, it should not be used in production without:
- Comprehensive security audit
- Penetration testing
- Compliance verification
- Additional environment-specific controls

## 📧 Support

For questions about the security implementations, refer to:
- OWASP documentation
- Security best practices guides
- Web security standards

---

**Remember**: Security is a journey, not a destination. Keep learning, keep improving, and always stay vigilant!
