# ShopVuln Red Team JavaScript Files - Complete Index

## 📁 File Structure

```
/frontend/apps/shopvuln/red/js/
├── api.js                          # Base API configuration
├── cart.js                         # Shopping cart (price manipulation)
├── checkout.js                     # Payment processing (bypass vulnerability)
├── coupons.js                      # Coupon management (stacking vulnerability)
├── products.js                     # Product display (SQL injection)
├── reviews.js                      # Product reviews (XSS vulnerability)
├── utils.js                        # Utility functions (no sanitization)
├── README.md                       # Comprehensive documentation
├── VULNERABILITIES_SUMMARY.md      # Quick exploitation guide
└── INDEX.md                        # This file
```

## 🎯 File Purposes

| File | Lines | Size | Purpose | Primary Vulnerability |
|------|-------|------|---------|----------------------|
| **api.js** | 83 | 2.1KB | API communication wrapper | No CSRF, no validation |
| **utils.js** | 231 | 6.2KB | Helper functions | No sanitization, innerHTML |
| **products.js** | 275 | 9.0KB | Product listing & search | SQL Injection |
| **cart.js** | 341 | 11KB | Shopping cart management | Price Manipulation |
| **checkout.js** | 363 | 12KB | Checkout & payment | Payment Bypass |
| **reviews.js** | 361 | 13KB | Review submission/display | XSS (Cross-Site Scripting) |
| **coupons.js** | 474 | 15KB | Coupon application | Coupon Stacking |

**Total**: 2,128 lines, ~80KB

---

## 🔗 File Dependencies

```
api.js (Base)
    ↓
utils.js (Helpers)
    ↓
    ├── products.js → cart.js → checkout.js
    ├── reviews.js
    └── coupons.js → checkout.js
```

### Import Chain:
1. All files import from `api.js`
2. All files import utilities from `utils.js`
3. `cart.js`, `checkout.js`, and `coupons.js` work together
4. `products.js` and `reviews.js` are independent modules

---

## 🚀 Quick Start Guide

### 1. Include in HTML

```html
<!-- Base dependencies (required first) -->
<script type="module" src="js/api.js"></script>
<script type="module" src="js/utils.js"></script>

<!-- Feature modules (as needed) -->
<script type="module" src="js/products.js"></script>
<script type="module" src="js/cart.js"></script>
<script type="module" src="js/checkout.js"></script>
<script type="module" src="js/reviews.js"></script>
<script type="module" src="js/coupons.js"></script>
```

### 2. HTML Page Requirements

Each module expects certain HTML elements:

**products.js** requires:
- `#search-input` - Search text field
- `#search-btn` - Search button
- `#category-filter` - Category dropdown
- `#products-container` - Product display area

**cart.js** requires:
- `#cart-container` - Cart items container
- `#cart-count` - Cart item counter badge

**checkout.js** requires:
- `#checkout-form` - Checkout form
- `#order-summary` - Order summary display
- `#total-amount` - Hidden total input

**reviews.js** requires:
- `#review-form` - Review submission form
- `#reviews-container` - Reviews display area
- `#rating-input` - Rating input field

**coupons.js** requires:
- `#coupon-code-input` - Coupon input field
- `#apply-coupon-btn` - Apply button
- `#applied-coupons-container` - Applied coupons list
- `#order-subtotal` - Order subtotal element

---

## 🐛 Vulnerability Matrix

| File | SQL Injection | XSS | Price Manipulation | Payment Bypass | Logic Flaw | CSRF |
|------|:------------:|:---:|:-----------------:|:-------------:|:----------:|:----:|
| api.js | - | - | - | - | - | ✓ |
| utils.js | - | ✓ | ✓ | - | - | - |
| products.js | ✓ | ✓ | ✓ | - | - | - |
| cart.js | - | - | ✓ | - | - | - |
| checkout.js | - | - | ✓ | ✓ | - | - |
| reviews.js | - | ✓ | - | - | - | - |
| coupons.js | - | - | ✓ | - | ✓ | - |

**Total Vulnerabilities**: 13 across 7 files

---

## 📚 Documentation Files

### README.md
- **Size**: ~10KB
- **Purpose**: Comprehensive documentation
- **Contents**: 
  - File descriptions
  - Vulnerability explanations
  - Code examples
  - OWASP mappings
  - Best practices (what NOT to do)

### VULNERABILITIES_SUMMARY.md  
- **Size**: ~8KB
- **Purpose**: Quick penetration testing guide
- **Contents**:
  - Exploitation examples
  - Browser console commands
  - Attack chains
  - Training scenarios
  - Automated scripts

### INDEX.md (This File)
- **Size**: ~4KB
- **Purpose**: Navigation and reference
- **Contents**:
  - File structure
  - Dependencies
  - Quick start guide
  - Cheat sheet

---

## 🎓 Learning Path

### Phase 1: Understanding (Read Code)
1. Start with `api.js` - understand API structure
2. Read `utils.js` - see vulnerable helper functions
3. Review each feature file to identify vulnerabilities

### Phase 2: Exploitation (Browser Console)
1. **products.js**: Try SQL injection in search
2. **reviews.js**: Submit XSS payload
3. **cart.js**: Modify prices in localStorage
4. **coupons.js**: Stack multiple coupons
5. **checkout.js**: Bypass payment process

### Phase 3: Automation (Write Scripts)
1. Write automated SQL injection scanner
2. Create XSS payload fuzzer
3. Build price manipulation tool
4. Develop full exploitation chain

### Phase 4: Defense (Compare with Blue Team)
1. Compare vulnerable vs. secure versions
2. Identify mitigation techniques
3. Implement fixes
4. Test security improvements

---

## 🔧 Testing Checklist

### Manual Testing
- [ ] SQL Injection in product search
- [ ] XSS in review submission
- [ ] Price manipulation via localStorage
- [ ] Price manipulation via DOM
- [ ] Coupon stacking (same coupon multiple times)
- [ ] Coupon stacking (different coupons)
- [ ] Custom coupon creation
- [ ] Payment bypass via hidden field
- [ ] Payment bypass via function call
- [ ] Negative quantity in cart
- [ ] Zero total checkout
- [ ] Session data tampering

### Automated Testing
- [ ] Run SQL injection wordlist
- [ ] Test XSS payloads from OWASP
- [ ] Fuzz coupon codes
- [ ] Brute force discount combinations
- [ ] API endpoint enumeration
- [ ] Parameter tampering tests

---

## 🛠️ Common Issues & Solutions

### Issue: "Manager not defined"
**Solution**: Ensure page has loaded completely
```javascript
// Wait for manager initialization
setTimeout(() => {
    window.cartManager.modifyItemPrice('123', 0.01);
}, 1000);
```

### Issue: "localStorage quota exceeded"
**Solution**: Clear localStorage
```javascript
localStorage.clear();
```

### Issue: "Cannot read property of undefined"
**Solution**: Check if HTML elements exist
```javascript
// Before exploitation, verify elements
if(document.getElementById('cart-container')) {
    // Exploit here
}
```

---

## 📊 Metrics

### Code Complexity
- **Cyclomatic Complexity**: Intentionally high (many vulnerable paths)
- **Lines of Code**: ~2,100
- **Functions**: ~80+
- **Classes**: 5 (one per feature module)

### Vulnerability Density
- **Critical**: 4 vulnerabilities
- **High**: 3 vulnerabilities  
- **Medium**: 6 vulnerabilities
- **Per File Average**: ~2 vulnerabilities

---

## 🔗 External Resources

### OWASP References
- [A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [A04:2021 - Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

### Testing Tools
- Browser DevTools Console
- Burp Suite (for API testing)
- OWASP ZAP
- SQLMap (for SQL injection)
- XSStrike (for XSS)

---

## 📝 Notes

### Design Decisions
1. **ES6+ Modules**: Modern JavaScript for readability
2. **Class-Based**: Organized, testable structure
3. **Verbose Comments**: Clear vulnerability markers
4. **Realistic Features**: Real e-commerce functionality
5. **localStorage**: Demonstrates client-side storage risks

### Educational Value
- Real-world vulnerability patterns
- Common developer mistakes
- Client-side trust issues
- Business logic flaws
- Input validation importance

---

## ⚡ Quick Commands Cheat Sheet

```javascript
// RECONNAISSANCE
Object.keys(window).filter(k => k.includes('Manager'))

// EXPLOITATION  
window.productManager.searchProducts("' OR 1=1--")
window.cartManager.modifyItemPrice('id', 0.01)
window.checkoutManager.bypassPayment()
window.couponManager.createCustomCoupon('FREE', 'percentage', 100)

// DATA MANIPULATION
localStorage.setItem('shopping_cart', '{"items":[]}')
document.getElementById('total-amount').value = '0.01'

// EXFILTRATION
console.log(localStorage.getItem('userSession'))
console.log(window.cartManager.exportCart())
```

---

**Version**: 1.0 (Red Team - Vulnerable)  
**Last Updated**: 2024  
**Part of**: AegisForge Security Training Platform  
**License**: Educational Use Only

⚠️ **WARNING**: Intentionally vulnerable code - DO NOT use in production!
