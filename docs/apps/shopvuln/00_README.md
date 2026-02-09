# ShopVuln - E-Commerce Security Training Platform

Complete e-commerce application demonstrating 7 critical vulnerabilities.

## Quick Start

1. Initialize database: `cd backend/apps/shopvuln && python database.py && python seed_data.py`
2. Run Red Team API: `python shopvuln_red_api.py` (port 5002)
3. Run Blue Team API: `python shopvuln_blue_api.py` (port 5003)
4. Open frontend: `frontend/apps/shopvuln/red/index.html`

## Vulnerabilities

1. SQL Injection - Product search
2. Price Manipulation - Shopping cart
3. Coupon Stacking - Discount logic
4. Stored XSS - Product reviews
5. IDOR - Order access
6. Payment Bypass - Checkout
7. Race Condition - Inventory

## Test Credentials

- alice / password123
- bob / securepass456
- admin / admin123

See full documentation in guides 01-17.
