# Blue Team JavaScript - Quick Reference Card

## 🚀 Quick Start

### Load Scripts (in order)
```html
<meta name="csrf-token" content="{{ csrf_token }}">
<script src="/static/shopvuln/blue/js/utils.js"></script>
<script src="/static/shopvuln/blue/js/api.js"></script>
<script src="/static/shopvuln/blue/js/products.js"></script>
<script src="/static/shopvuln/blue/js/cart.js"></script>
<script src="/static/shopvuln/blue/js/checkout.js"></script>
<script src="/static/shopvuln/blue/js/reviews.js"></script>
<script src="/static/shopvuln/blue/js/coupons.js"></script>
```

## 🛡️ Security Cheat Sheet

### ✅ DO THIS (Secure)
```javascript
// XSS Prevention
element.textContent = userInput;  // ✅ Safe
element.textContent = SecureUtils.sanitizeInput(userInput);  // ✅ Even safer

// Input Validation
if (SecureUtils.validateEmail(email)) { /* ... */ }  // ✅ Good
if (SecureUtils.validateInteger(qty, 1, 100)) { /* ... */ }  // ✅ Good

// API Calls with CSRF
await SecureAPI.post('/endpoint', data);  // ✅ CSRF token automatic

// Price Display (server prices only)
price.textContent = SecureUtils.formatPrice(serverPrice);  // ✅ Good
```

### ❌ DON'T DO THIS (Vulnerable)
```javascript
// XSS Vulnerability
element.innerHTML = userInput;  // ❌ DANGEROUS!

// No Validation
const price = parseFloat(input.value);  // ❌ No validation!

// Missing CSRF
fetch('/api/endpoint', { method: 'POST' });  // ❌ No CSRF token!

// Client-side Price Calculation
total = price * quantity;  // ❌ Client can manipulate!
```

## 📚 Common Functions

### SecureUtils (utils.js)

```javascript
// HTML Encoding
SecureUtils.encodeHTML(str)  // Convert to HTML entities

// Input Sanitization
SecureUtils.sanitizeInput(input, maxLength)  // Clean and limit length

// Validation
SecureUtils.validateEmail(email)  // Email validation
SecureUtils.validatePhone(phone)  // Phone validation
SecureUtils.validateCreditCard(number)  // Luhn algorithm
SecureUtils.validateInteger(value, min, max)  // Integer range
SecureUtils.validateNumber(value, min, max)  // Number range
SecureUtils.validateLength(str, min, max)  // String length

// CSRF Tokens
SecureUtils.getCSRFToken()  // Get current token
SecureUtils.setCSRFToken(token)  // Set new token

// Display Messages
SecureUtils.showError(message, containerId)  // Show error
SecureUtils.showSuccess(message, containerId)  // Show success

// Safe DOM Manipulation
SecureUtils.setTextContent(element, text)  // Safe set
SecureUtils.createElementWithText(tag, text, className)  // Create safely

// Formatting
SecureUtils.formatPrice(price)  // Display price
SecureUtils.debounce(func, wait)  // Rate limiting
```

### SecureAPI (api.js)

```javascript
// Generic Requests
SecureAPI.get(endpoint, params)  // GET request
SecureAPI.post(endpoint, data)  // POST with CSRF
SecureAPI.put(endpoint, data)  // PUT with CSRF
SecureAPI.delete(endpoint)  // DELETE with CSRF

// Products
SecureAPI.products.getAll(params)  // List products
SecureAPI.products.getById(id)  // Get single product
SecureAPI.products.search(query)  // Search products

// Cart
SecureAPI.cart.get()  // Get cart
SecureAPI.cart.add(productId, quantity)  // Add item
SecureAPI.cart.update(itemId, quantity)  // Update quantity
SecureAPI.cart.remove(itemId)  // Remove item
SecureAPI.cart.clear()  // Clear cart

// Coupons
SecureAPI.coupons.validate(code)  // Validate coupon
SecureAPI.coupons.apply(code)  // Apply coupon
SecureAPI.coupons.remove()  // Remove coupon

// Checkout
SecureAPI.checkout.validateCart()  // Validate before checkout
SecureAPI.checkout.submit(data)  // Submit order

// Reviews
SecureAPI.reviews.getByProduct(productId)  // Get reviews
SecureAPI.reviews.submit(productId, rating, comment)  // Submit review
```

## 🎯 Common Patterns

### Pattern 1: Display User Content Safely
```javascript
// ALWAYS use textContent for user content
const name = document.createElement('h3');
name.textContent = SecureUtils.sanitizeInput(product.name, 100);

// NEVER use innerHTML for user content
// name.innerHTML = product.name;  // ❌ DON'T DO THIS!
```

### Pattern 2: Validate Input Before Sending
```javascript
// Validate on client (UX) and server (security)
const email = form.querySelector('#email').value;

if (!SecureUtils.validateEmail(email)) {
    SecureUtils.showError('Invalid email address');
    return;
}

// Server will validate again
await SecureAPI.post('/endpoint', { 
    email: SecureUtils.sanitizeInput(email, 254) 
});
```

### Pattern 3: Handle Prices Securely
```javascript
// ✅ CORRECT: Get price from server
const response = await SecureAPI.cart.get();
total.textContent = SecureUtils.formatPrice(response.data.total);

// ❌ WRONG: Calculate price on client
// const total = price * quantity;  // DON'T DO THIS!
```

### Pattern 4: Submit Forms with CSRF
```javascript
// SecureAPI handles CSRF automatically
const formData = {
    name: SecureUtils.sanitizeInput(form.name.value, 100),
    email: SecureUtils.sanitizeInput(form.email.value, 254)
};

await SecureAPI.post('/submit', formData);  // CSRF token added automatically
```

### Pattern 5: Rate Limiting
```javascript
// Debounce search to prevent spam
searchInput.addEventListener('input', SecureUtils.debounce((e) => {
    handleSearch(e.target.value);
}, 500));  // 500ms delay
```

## ⚠️ Security Checklist

Before deploying, verify:

- [ ] All user input displayed with `textContent`
- [ ] All input validated client-side
- [ ] All input sanitized before API calls
- [ ] Server validates all input again
- [ ] CSRF tokens on all POST/PUT/DELETE
- [ ] Prices only from server, never client
- [ ] No sensitive data in URLs
- [ ] Error messages don't reveal secrets
- [ ] Rate limiting on user actions
- [ ] Session timeout configured
- [ ] HTTPS enabled in production
- [ ] Content Security Policy configured

## 🔧 Troubleshooting

### "Failed to load cart"
- Check server endpoint is running
- Verify session is valid
- Check CSRF token is present

### "Invalid CSRF token"
- Ensure meta tag in HTML: `<meta name="csrf-token" content="...">`
- Check token is being sent in headers
- Verify server is validating correctly

### "Price mismatch"
- This is expected! Server recalculates all prices
- Never trust client-side prices
- Display server prices only

### XSS test shows script
- Good! It should display as text, not execute
- If it executes, you're using innerHTML incorrectly

## 📖 File Responsibilities

| File | Purpose | Key Features |
|------|---------|--------------|
| **utils.js** | Security helpers | Sanitization, validation, CSRF |
| **api.js** | API communication | CSRF handling, error handling |
| **products.js** | Product display | Search, filtering, XSS prevention |
| **cart.js** | Shopping cart | Server prices, quantity validation |
| **checkout.js** | Order processing | Payment validation, CSRF |
| **reviews.js** | Product reviews | XSS prevention, rating validation |
| **coupons.js** | Coupon handling | Server validation, rate limiting |

## 🎓 Learning Resources

- **XSS Prevention**: Always use `textContent`, never `innerHTML` for user data
- **CSRF Protection**: Include tokens on all state changes (POST/PUT/DELETE)
- **Input Validation**: Validate format, length, type, and range
- **Server Trust**: All prices, discounts, and calculations from server
- **Defense in Depth**: Multiple layers of security (client + server)

## 💡 Quick Tips

1. **Sanitize Early**: Clean input as soon as you receive it
2. **Validate Always**: Client for UX, server for security
3. **Trust Nothing**: Assume all client data is malicious
4. **Encode Output**: HTML-encode before display
5. **Use Helpers**: Don't reinvent security functions
6. **Test Security**: Try to break your own code
7. **Read Comments**: Each file has detailed security notes

---

**Remember:** Security is not optional. Every line of code is a potential vulnerability.

**Golden Rule:** If it comes from the user, it's dangerous until proven safe!
