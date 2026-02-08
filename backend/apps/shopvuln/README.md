# ShopVuln Backend

Educational e-commerce application backend for AegisForge demonstrating both vulnerable and secure implementations.

## Structure

```
backend/apps/shopvuln/
├── __init__.py                  # Package initialization
├── models.py                    # SQLAlchemy database models
├── database.py                  # Database initialization and connection
├── seed_data.py                 # Sample data seeding script
├── shopvuln_red_api.py         # Red Team (Vulnerable) API
├── shopvuln_blue_api.py        # Blue Team (Secure) API
└── README.md                    # This file
```

## Quick Start

### 1. Initialize Database

```bash
cd backend/apps/shopvuln
python database.py
```

### 2. Seed Sample Data

```bash
python seed_data.py
```

This creates:
- 4 test users (alice, bob, admin, carol)
- 20 products across various categories
- 8 sample product reviews
- 4 discount coupons
- 3 sample orders with items
- Shopping cart items for testing

### 3. Run Red Team (Vulnerable) API

```bash
python shopvuln_red_api.py
```

Runs on: `http://localhost:5002`

### 4. Run Blue Team (Secure) API

```bash
python shopvuln_blue_api.py
```

Runs on: `http://localhost:5003`

## Test Credentials

- **Username:** alice | **Password:** password123
- **Username:** bob | **Password:** securepass456
- **Username:** admin | **Password:** admin123
- **Username:** carol | **Password:** carol789

## Test Coupons

- **SAVE20** - 20% off orders over $100
- **WELCOME10** - 10% off orders over $50
- **FREESHIP** - $9.99 off shipping on orders over $75
- **BLACKFRIDAY50** - 50% off orders over $200

## Vulnerabilities (Red Team)

1. **SQL Injection** - Product search endpoint
2. **Price Manipulation** - Shopping cart endpoint
3. **Coupon Stacking** - Coupon application logic
4. **Stored XSS** - Product reviews
5. **IDOR** - Order access endpoint
6. **Payment Bypass** - Checkout completion
7. **Race Condition** - Inventory management

## Security Features (Blue Team)

1. **Parameterized Queries** - Prevents SQL injection
2. **Server-Side Validation** - Prevents price manipulation
3. **Business Logic Checks** - Prevents coupon stacking
4. **Output Encoding** - Prevents XSS
5. **Authorization Checks** - Prevents IDOR
6. **Payment Verification** - Prevents payment bypass
7. **Transaction Locking** - Prevents race conditions

## API Endpoints

### Authentication
- `POST /api/{team}/shopvuln/login` - User login
- `POST /api/{team}/shopvuln/logout` - User logout
- `GET /api/{team}/shopvuln/session` - Get session info
- `GET /api/blue/shopvuln/csrf-token` - Get CSRF token (Blue only)

### Products
- `GET /api/{team}/shopvuln/products` - List all products
- `GET /api/{team}/shopvuln/products/<id>` - Get specific product
- `GET /api/{team}/shopvuln/search` - Search products (VULNERABLE in Red)
- `GET /api/{team}/shopvuln/categories` - Get product categories

### Shopping Cart
- `POST /api/{team}/shopvuln/cart/add` - Add item to cart (VULNERABLE in Red)
- `GET /api/{team}/shopvuln/cart` - Get cart items
- `PUT /api/{team}/shopvuln/cart/<id>` - Update cart item
- `DELETE /api/{team}/shopvuln/cart/<id>` - Remove cart item
- `DELETE /api/{team}/shopvuln/cart` - Clear cart

### Reviews
- `POST /api/{team}/shopvuln/reviews/add` - Add review (VULNERABLE in Red)
- `GET /api/{team}/shopvuln/reviews/<product_id>` - Get product reviews

### Orders
- `GET /api/{team}/shopvuln/orders` - Get user's orders
- `GET /api/{team}/shopvuln/orders/<id>` - Get specific order (VULNERABLE in Red)

### Checkout
- `POST /api/{team}/shopvuln/checkout/apply-coupon` - Apply coupon (VULNERABLE in Red)
- `POST /api/{team}/shopvuln/checkout/complete` - Complete checkout (VULNERABLE in Red)
- `POST /api/{team}/shopvuln/checkout/purchase` - Purchase (VULNERABLE in Red)

### Coupons
- `GET /api/{team}/shopvuln/coupons` - List available coupons
- `POST /api/{team}/shopvuln/coupons/validate` - Validate coupon

## Database Schema

### Tables
- **shop_users** - User accounts
- **products** - Product catalog
- **reviews** - Product reviews
- **orders** - Customer orders
- **order_items** - Items in each order
- **cart_items** - Shopping cart items
- **coupons** - Discount coupons
- **coupon_usages** - Coupon usage tracking

## Security Notes

⚠️ **Red Team API**: Contains intentional vulnerabilities for educational purposes. NEVER use in production.

✅ **Blue Team API**: Demonstrates secure coding practices and should be used as a reference for secure implementation.

## Learning Path

1. Start with the Red Team API to understand common e-commerce vulnerabilities
2. Practice exploiting each vulnerability using tools like Burp Suite, SQLMap, and Postman
3. Study the Blue Team API to learn proper security implementations
4. Compare the differences between vulnerable and secure code
5. Apply these lessons to real-world e-commerce applications

## Additional Resources

- See `docs/apps/shopvuln/` for detailed vulnerability guides
- Check frontend applications in `frontend/apps/shopvuln/` for UI demonstrations
- Review testing guides for hands-on exploitation practice
