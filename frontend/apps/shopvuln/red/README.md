# ShopVuln Red Team Frontend - HTML Pages

## Overview
Professional e-commerce HTML pages for ShopVuln Red Team security testing platform. Each page includes intentional vulnerabilities for educational purposes.

## Files Created

### 1. **index.html** (12.9 KB)
- Homepage with product grid and featured items
- Category filters for browsing
- Hero banner and newsletter subscription
- **Vulnerabilities**: XSS in search, session fixation, unsanitized product data

### 2. **search.html** (16.5 KB)
- Product search results page
- Advanced filtering sidebar (category, price, rating)
- Sortable results grid
- Pagination controls
- **Vulnerabilities**: XSS in search query display, SQL injection in filters/sort, parameter manipulation

### 3. **product.html** (23.4 KB)
- Detailed product page with image gallery
- Product specifications and descriptions
- Customer reviews section with ratings
- Review submission modal
- Product tabs (Reviews, Specs, Shipping)
- **Vulnerabilities**: IDOR via product ID, Stored XSS in reviews/descriptions, unsanitized user input

### 4. **cart.html** (16.0 KB)
- Shopping cart with item management
- Quantity controls and removal options
- Order summary with totals
- Coupon code application
- Recommended products section
- **Vulnerabilities**: Client-side quantity manipulation, localStorage cart without encryption, coupon validation bypass

### 5. **checkout.html** (18.8 KB)
- Multi-section checkout form
- Shipping information collection
- Payment method selection (Card/PayPal)
- Shipping method options
- Order summary sidebar
- **Vulnerabilities**: Missing CSRF protection, insecure card data transmission, client-side price manipulation

### 6. **orders.html** (17.9 KB)
- Order history with filtering
- Order status tracking
- Detailed order information modal
- Invoice download functionality
- Order cancellation/reordering
- **Vulnerabilities**: IDOR with predictable order IDs, unauthorized order access, order manipulation

### 7. **coupon.html** (23.0 KB)
- Coupon browsing and management
- Coupon code validation
- Custom coupon generator (demo feature)
- Saved coupons section
- Referral program with link sharing
- **Vulnerabilities**: Coupon enumeration, brute force, exposed codes in HTML, predictable referral IDs, unauthorized coupon generation

## Design Features

### Color Scheme
- **Primary**: #6366f1 (Indigo)
- **Secondary**: #8b5cf6 (Purple)
- **Success**: #10b981 (Green)
- **Warning**: #f59e0b (Orange)
- **Danger**: #ef4444 (Red)

### Common Components
- Responsive navigation header with logo, search bar, cart icon, and user menu
- Consistent footer with links and social media icons
- Professional product cards with ratings and pricing
- Modern form controls and buttons
- Modal dialogs for interactive features
- Toast notifications for user feedback

### External Dependencies
- Font Awesome 6.4.0 (icons)
- CSS files in `css/` directory (to be implemented)
- JavaScript files in `js/` directory (to be implemented)

## Vulnerability Categories

### Cross-Site Scripting (XSS)
- Reflected XSS in search parameters
- Stored XSS in product reviews
- DOM-based XSS in dynamic content loading

### Injection Attacks
- SQL injection in category filters
- SQL injection in sort parameters
- Command injection possibilities

### Broken Authentication & Session Management
- Session fixation vulnerabilities
- Weak session handling
- Missing CSRF tokens

### Insecure Direct Object References (IDOR)
- Predictable product IDs
- Sequential order numbers
- User ID exposure in referral links

### Security Misconfiguration
- Client-side validation only
- Sensitive data in localStorage
- Missing security headers
- Insecure payment data handling

### Business Logic Flaws
- Price manipulation
- Coupon code enumeration
- Quantity override
- Unauthorized coupon generation

## Testing Scenarios

Each page supports multiple attack vectors:
- **XSS**: Test input fields, URL parameters, and user-generated content
- **SQL Injection**: Filter parameters, search queries, sorting options
- **CSRF**: Form submissions without tokens
- **IDOR**: Manipulate IDs in URLs and requests
- **Business Logic**: Bypass validation, manipulate prices/quantities

## Integration Points

Pages link to:
- CSS: `css/main.css`, `css/[page].css`
- JavaScript: `js/main.js`, `js/[page].js`, `js/cart.js`
- External: Font Awesome CDN, placeholder images via placeholder.com

## Usage

These pages are designed for:
1. Security training and education
2. Penetration testing practice
3. Red team exercises
4. Vulnerability assessment demonstrations
5. Secure coding workshops

**Note**: These vulnerabilities are intentional for educational purposes. Never deploy vulnerable code in production environments.

## Next Steps

To complete the frontend:
1. Implement CSS files for styling
2. Create JavaScript files for functionality
3. Connect to backend API endpoints
4. Add proper error handling
5. Implement security testing tools integration

---

Created for AegisForge Security Training Platform
