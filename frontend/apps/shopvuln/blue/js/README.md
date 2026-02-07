# ShopVuln Blue Team - Secure JavaScript Files

## Overview

This directory contains the **SECURE (Blue Team)** versions of all ShopVuln JavaScript files. These files demonstrate security best practices and protect against common web vulnerabilities.

## Files Created

### 1. **utils.js** - Security Utility Functions
**Security Improvements:**
- ✅ HTML encoding to prevent XSS attacks
- ✅ Input validation and sanitization helpers
- ✅ SQL injection prevention utilities
- ✅ Proper error handling
- ✅ CSRF token management
- ✅ Secure string operations with length limits
- ✅ Credit card validation (Luhn algorithm)
- ✅ Email and phone validation
- ✅ Safe JSON parsing
- ✅ Debounce function for rate limiting

### 2. **api.js** - Secure API Handler
**Security Improvements:**
- ✅ CSRF token in all state-changing requests (POST/PUT/DELETE)
- ✅ Request timeout handling (30 seconds)
- ✅ Security headers (X-Requested-With)
- ✅ Same-origin credentials only
- ✅ Proper error handling and validation
- ✅ Input sanitization before API calls
- ✅ No sensitive data in URLs (uses POST body)
- ✅ Automatic CSRF token refresh

### 3. **products.js** - Secure Product Display
**Security Improvements:**
- ✅ Removed SQL injection vulnerabilities (server-side parameterized queries)
- ✅ XSS prevention using `textContent` instead of `innerHTML`
- ✅ Input sanitization on search queries
- ✅ Proper output encoding for all product data
- ✅ Server-side validation for all operations
- ✅ No client-side price manipulation possible
- ✅ Debounced search (rate limiting)
- ✅ Secure image URL validation
- ✅ Pagination with safe navigation

### 4. **cart.js** - Secure Shopping Cart
**Security Improvements:**
- ✅ **Server-side price validation** - prices NEVER trusted from client
- ✅ All price calculations done server-side
- ✅ Cart manipulation requires server verification
- ✅ Quantity validation (min: 1, max: 100)
- ✅ CSRF protection on all cart modifications
- ✅ XSS prevention using `textContent`
- ✅ No client-side price/total manipulation possible
- ✅ Session-based cart storage (server-side)

### 5. **checkout.js** - Secure Checkout Process
**Security Improvements:**
- ✅ **Server-side payment verification** - no client-side bypass
- ✅ CSRF token protection on form submission
- ✅ Input validation and sanitization
- ✅ Credit card validation (Luhn algorithm)
- ✅ Expiry date validation
- ✅ Secure form handling
- ✅ Server-side price verification
- ✅ XSS prevention
- ✅ Double-submission prevention
- ✅ Rate limiting awareness
- ✅ Session validation before payment

### 6. **reviews.js** - Secure Product Reviews
**Security Improvements:**
- ✅ **XSS prevention using `textContent`** instead of `innerHTML`
- ✅ Input sanitization on all user content
- ✅ HTML encoding for display
- ✅ CSRF protection on review submission
- ✅ Rate limiting on submissions
- ✅ Server-side rating validation (1-5)
- ✅ Content length limits (10-1000 chars)
- ✅ No script injection possible
- ✅ DOMPurify-compatible sanitization

### 7. **coupons.js** - Secure Coupon Handler
**Security Improvements:**
- ✅ **Server-side coupon validation only**
- ✅ No client-side coupon generation
- ✅ Prevention of coupon stacking abuse
- ✅ Server-side usage tracking
- ✅ Expiration validation server-side
- ✅ CSRF protection on application
- ✅ Input sanitization on codes
- ✅ Rate limiting (5 attempts per minute)
- ✅ No discount calculation client-side

## Key Security Principles

### 1. **Never Trust Client-Side Data**
- All prices come from the server
- All validation is duplicated server-side
- Client-side validation is for UX only

### 2. **XSS Prevention**
- Always use `textContent` instead of `innerHTML`
- HTML encode all user input
- Sanitize before display
- Use Content Security Policy

### 3. **CSRF Protection**
- CSRF tokens on all state-changing requests
- Automatic token refresh
- SameSite cookie attributes

### 4. **Input Validation**
- Whitelist validation (allow known good)
- Length limits on all inputs
- Type validation (email, phone, numbers)
- Server-side enforcement

### 5. **SQL Injection Prevention**
- Server-side parameterized queries
- No raw SQL from client input
- Input sanitization

### 6. **Rate Limiting**
- Debounced search queries
- Limited coupon validation attempts
- Checkout submission throttling

### 7. **Secure Session Management**
- Server-side cart storage
- Session validation
- Timeout handling

## Usage

### Including in HTML
```html
<!-- Load utilities first -->
<script src="/static/shopvuln/blue/js/utils.js"></script>
<script src="/static/shopvuln/blue/js/api.js"></script>

<!-- Then load page-specific scripts -->
<script src="/static/shopvuln/blue/js/products.js"></script>
<script src="/static/shopvuln/blue/js/cart.js"></script>
<script src="/static/shopvuln/blue/js/checkout.js"></script>
<script src="/static/shopvuln/blue/js/reviews.js"></script>
<script src="/static/shopvuln/blue/js/coupons.js"></script>
```

### API Endpoints
All files expect server endpoints at `/api/blue/shopvuln/`:
- `/api/blue/shopvuln/products` - Product operations
- `/api/blue/shopvuln/cart` - Cart operations
- `/api/blue/shopvuln/checkout` - Checkout operations
- `/api/blue/shopvuln/coupons` - Coupon operations
- `/api/blue/shopvuln/products/:id/reviews` - Review operations

### CSRF Token Setup
Add this to your HTML `<head>`:
```html
<meta name="csrf-token" content="{{ csrf_token }}">
```

## Comparison: Red Team vs Blue Team

### Red Team Vulnerabilities (FIXED in Blue Team)

| Vulnerability | Red Team | Blue Team |
|---------------|----------|-----------|
| **SQL Injection** | Raw SQL queries | Parameterized queries (server) |
| **XSS** | Uses innerHTML | Uses textContent |
| **Price Manipulation** | Client-side prices | Server-side validation |
| **CSRF** | No protection | CSRF tokens |
| **Coupon Abuse** | Client-side validation | Server-side validation |
| **Input Validation** | Minimal/none | Comprehensive |
| **Rate Limiting** | None | Debouncing + server limits |
| **Session Security** | Weak | Strong server-side |

## Testing the Security

### Test XSS Protection
Try entering in reviews:
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
```
**Result:** Displayed as plain text, not executed

### Test Price Manipulation
Try modifying cart prices in browser DevTools:
**Result:** Server recalculates and validates

### Test SQL Injection
Try searching for:
```sql
'; DROP TABLE products; --
' OR '1'='1
```
**Result:** Treated as literal search string

### Test CSRF
Try submitting forms without CSRF token:
**Result:** Request rejected by server

## Educational Value

These files demonstrate:
1. ✅ Secure coding practices
2. ✅ OWASP Top 10 mitigations
3. ✅ Defense in depth
4. ✅ Client-server security model
5. ✅ Input validation strategies
6. ✅ Modern JavaScript security patterns

## Next Steps

1. Deploy these files alongside secure backend API
2. Configure Content Security Policy headers
3. Set up proper session management
4. Implement rate limiting on server
5. Add security monitoring and logging
6. Regular security audits

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

**Created for AegisForge Educational Platform**
*Teaching secure web development through hands-on practice*
