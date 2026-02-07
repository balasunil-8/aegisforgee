"""
ShopVuln Red Team API - VULNERABLE VERSION
WARNING: This code contains intentional security vulnerabilities for educational purposes.
NEVER use this code in production.

Demonstrates 7 major e-commerce vulnerabilities:
1. SQL Injection (Product Search)
2. Price Manipulation (Shopping Cart)
3. Coupon Stacking (Checkout)
4. Stored XSS (Product Reviews)
5. IDOR - Insecure Direct Object References (Order Access)
6. Payment Bypass (Checkout Completion)
7. Race Condition (Inventory Management)
"""

from flask import Flask, request, jsonify, session
from flask_cors import CORS
import sqlite3
from datetime import datetime, timedelta
import os
import time
import threading
import random
import string

# Database configuration
DB_PATH = os.path.join(os.path.dirname(__file__), 'shopvuln.db')

# Lock for race condition demo (intentionally not used in vulnerable version)
inventory_lock = threading.Lock()


def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def generate_order_number():
    """Generate unique order number"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_part = ''.join(random.choices(string.digits, k=4))
    return f"ORD-{timestamp}-{random_part}"


def create_red_team_api():
    """Create Flask app with vulnerable endpoints"""
    app = Flask(__name__)
    app.secret_key = 'shop-vuln-secret-123'  # VULNERABLE: Weak secret key
    
    # VULNERABLE: Wide open CORS
    CORS(app, supports_credentials=True, resources={
        r"/api/red/shopvuln/*": {"origins": "*"}
    })
    
    # ============================================================================
    # AUTHENTICATION ENDPOINTS
    # ============================================================================
    
    @app.route('/api/red/shopvuln/login', methods=['POST'])
    def red_login():
        """Login endpoint - basic authentication"""
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        
        try:
            conn = get_db()
            # Using parameterized query for login (not the vulnerable part)
            cursor = conn.execute(
                'SELECT * FROM shop_users WHERE username = ? AND password = ?',
                (username, password)
            )
            user = cursor.fetchone()
            conn.close()
            
            if user:
                # Store user in session
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                
                return jsonify({
                    'success': True,
                    'user': {
                        'id': user['id'],
                        'username': user['username'],
                        'full_name': user['full_name'],
                        'email': user['email'],
                        'role': user['role']
                    },
                    'message': 'Login successful'
                }), 200
            else:
                return jsonify({
                    'success': False,
                    'error': 'Invalid credentials'
                }), 401
                
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/red/shopvuln/logout', methods=['POST'])
    def red_logout():
        """Logout endpoint"""
        session.clear()
        return jsonify({'success': True, 'message': 'Logged out'}), 200
    
    @app.route('/api/red/shopvuln/session', methods=['GET'])
    def red_get_session():
        """Get current session info"""
        if 'user_id' in session:
            return jsonify({
                'authenticated': True,
                'user': {
                    'id': session.get('user_id'),
                    'username': session.get('username'),
                    'role': session.get('role')
                }
            }), 200
        return jsonify({'authenticated': False}), 200
    
    # ============================================================================
    # VULNERABILITY #1: SQL INJECTION (Product Search)
    # ============================================================================
    
    @app.route('/api/red/shopvuln/search', methods=['GET'])
    def red_search_products():
        """
        VULNERABLE: SQL Injection in product search
        Attack: query = " OR '1'='1' --
        Attack: query = " UNION SELECT id,username,password,email,4,5,6,7,8,9 FROM shop_users --
        """
        search_query = request.args.get('query', '')
        category = request.args.get('category', '')
        
        try:
            conn = get_db()
            
            # VULNERABLE: Direct string concatenation - SQL Injection
            if category:
                query = f"SELECT * FROM products WHERE category = '{category}' AND name LIKE '%{search_query}%'"
            else:
                query = f"SELECT * FROM products WHERE name LIKE '%{search_query}%' OR description LIKE '%{search_query}%'"
            
            cursor = conn.execute(query)  # DANGEROUS: No parameterization
            products = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return jsonify({
                'success': True,
                'products': products,
                'count': len(products)
            }), 200
            
        except Exception as e:
            # VULNERABLE: Leaking error details and query structure
            return jsonify({
                'success': False,
                'error': str(e),
                'query': query  # VULNERABLE: Exposing SQL query
            }), 500
    
    @app.route('/api/red/shopvuln/products', methods=['GET'])
    def red_get_products():
        """Get all products (safe endpoint for comparison)"""
        category = request.args.get('category')
        
        try:
            conn = get_db()
            
            if category:
                cursor = conn.execute(
                    'SELECT * FROM products WHERE category = ? ORDER BY name',
                    (category,)
                )
            else:
                cursor = conn.execute('SELECT * FROM products ORDER BY name')
            
            products = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return jsonify({
                'success': True,
                'products': products,
                'count': len(products)
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/red/shopvuln/products/<int:product_id>', methods=['GET'])
    def red_get_product(product_id):
        """Get single product details"""
        try:
            conn = get_db()
            cursor = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,))
            product = cursor.fetchone()
            conn.close()
            
            if product:
                return jsonify({
                    'success': True,
                    'product': dict(product)
                }), 200
            else:
                return jsonify({
                    'success': False,
                    'error': 'Product not found'
                }), 404
                
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/red/shopvuln/categories', methods=['GET'])
    def red_get_categories():
        """Get all product categories"""
        try:
            conn = get_db()
            cursor = conn.execute('SELECT DISTINCT category FROM products ORDER BY category')
            categories = [row['category'] for row in cursor.fetchall()]
            conn.close()
            
            return jsonify({
                'success': True,
                'categories': categories
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # ============================================================================
    # VULNERABILITY #2: PRICE MANIPULATION (Shopping Cart)
    # ============================================================================
    
    @app.route('/api/red/shopvuln/cart', methods=['GET'])
    def red_get_cart():
        """Get user's shopping cart"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        try:
            conn = get_db()
            cursor = conn.execute('''
                SELECT ci.*, p.name, p.category, p.description, p.image, p.stock
                FROM cart_items ci
                JOIN products p ON ci.product_id = p.id
                WHERE ci.user_id = ?
            ''', (user_id,))
            
            cart_items = []
            total = 0
            for row in cursor.fetchall():
                item = dict(row)
                item_total = item['price'] * item['quantity']
                item['item_total'] = item_total
                total += item_total
                cart_items.append(item)
            
            conn.close()
            
            return jsonify({
                'success': True,
                'cart': cart_items,
                'total': total,
                'item_count': len(cart_items)
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/red/shopvuln/cart/add', methods=['POST'])
    def red_add_to_cart():
        """
        VULNERABLE: Price Manipulation - Client controls price
        Attack: Send modified price in request body
        Example: {"product_id": 1, "quantity": 1, "price": 0.01}
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        data = request.get_json()
        
        product_id = data.get('product_id')
        quantity = int(data.get('quantity', 1))
        # VULNERABLE: Client sends price instead of server determining it
        price = float(data.get('price', 0))
        
        if not product_id or quantity <= 0:
            return jsonify({
                'success': False,
                'error': 'Invalid product or quantity'
            }), 400
        
        try:
            conn = get_db()
            
            # Check if item already in cart
            cursor = conn.execute(
                'SELECT * FROM cart_items WHERE user_id = ? AND product_id = ?',
                (user_id, product_id)
            )
            existing_item = cursor.fetchone()
            
            if existing_item:
                # Update quantity and price (VULNERABLE: Accepts new price from client)
                conn.execute(
                    'UPDATE cart_items SET quantity = quantity + ?, price = ? WHERE id = ?',
                    (quantity, price, existing_item['id'])
                )
            else:
                # VULNERABLE: Insert with client-provided price
                conn.execute('''
                    INSERT INTO cart_items (user_id, product_id, quantity, price)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, product_id, quantity, price))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Item added to cart'
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/red/shopvuln/cart/update/<int:item_id>', methods=['PUT'])
    def red_update_cart_item(item_id):
        """
        VULNERABLE: Price manipulation in cart updates
        Attack: Modify price when updating quantity
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        data = request.get_json()
        
        quantity = int(data.get('quantity', 1))
        # VULNERABLE: Client can modify price during update
        price = data.get('price')
        
        if quantity <= 0:
            return jsonify({
                'success': False,
                'error': 'Invalid quantity'
            }), 400
        
        try:
            conn = get_db()
            
            if price is not None:
                # VULNERABLE: Allows price update
                conn.execute(
                    'UPDATE cart_items SET quantity = ?, price = ? WHERE id = ? AND user_id = ?',
                    (quantity, float(price), item_id, user_id)
                )
            else:
                conn.execute(
                    'UPDATE cart_items SET quantity = ? WHERE id = ? AND user_id = ?',
                    (quantity, item_id, user_id)
                )
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Cart updated'
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/red/shopvuln/cart/remove/<int:item_id>', methods=['DELETE'])
    def red_remove_from_cart(item_id):
        """Remove item from cart"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        try:
            conn = get_db()
            conn.execute(
                'DELETE FROM cart_items WHERE id = ? AND user_id = ?',
                (item_id, user_id)
            )
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Item removed from cart'
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/red/shopvuln/cart/clear', methods=['DELETE'])
    def red_clear_cart():
        """Clear user's cart"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        try:
            conn = get_db()
            conn.execute('DELETE FROM cart_items WHERE user_id = ?', (user_id,))
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Cart cleared'
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # ============================================================================
    # VULNERABILITY #3: COUPON STACKING (Checkout)
    # ============================================================================
    
    @app.route('/api/red/shopvuln/coupons', methods=['GET'])
    def red_get_coupons():
        """Get all active coupons"""
        try:
            conn = get_db()
            cursor = conn.execute('''
                SELECT * FROM coupons 
                WHERE active = 1 AND datetime('now') BETWEEN valid_from AND valid_until
                ORDER BY discount_value DESC
            ''')
            coupons = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return jsonify({
                'success': True,
                'coupons': coupons
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/red/shopvuln/checkout/apply-coupon', methods=['POST'])
    def red_apply_coupon():
        """
        VULNERABLE: Coupon stacking - No check for multiple coupon usage
        Attack: Apply multiple coupons to same order by calling endpoint multiple times
        Attack: Use same coupon multiple times beyond max_uses_per_user
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        data = request.get_json()
        
        coupon_code = data.get('coupon_code', '').upper()
        cart_total = float(data.get('cart_total', 0))
        
        if not coupon_code:
            return jsonify({
                'success': False,
                'error': 'Coupon code required'
            }), 400
        
        try:
            conn = get_db()
            
            # Get coupon details
            cursor = conn.execute(
                'SELECT * FROM coupons WHERE code = ? AND active = 1',
                (coupon_code,)
            )
            coupon = cursor.fetchone()
            
            if not coupon:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Invalid coupon code'
                }), 404
            
            # Check validity dates
            now = datetime.now()
            valid_from = datetime.fromisoformat(coupon['valid_from'])
            valid_until = datetime.fromisoformat(coupon['valid_until'])
            
            if now < valid_from or now > valid_until:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Coupon has expired or not yet valid'
                }), 400
            
            # Check minimum purchase
            if cart_total < coupon['min_purchase']:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': f"Minimum purchase of ${coupon['min_purchase']} required"
                }), 400
            
            # VULNERABLE: No proper check for coupon stacking or usage limits
            # Should prevent multiple coupons on same order
            # Should enforce max_uses_per_user properly
            
            # Calculate discount
            if coupon['discount_type'] == 'percentage':
                discount = cart_total * (coupon['discount_value'] / 100)
            else:  # fixed
                discount = coupon['discount_value']
            
            # Cap discount at cart total
            discount = min(discount, cart_total)
            
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Coupon applied successfully',
                'coupon': {
                    'code': coupon['code'],
                    'discount_type': coupon['discount_type'],
                    'discount_value': coupon['discount_value']
                },
                'discount': discount,
                'new_total': cart_total - discount
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # ============================================================================
    # VULNERABILITY #4: STORED XSS (Product Reviews)
    # ============================================================================
    
    @app.route('/api/red/shopvuln/products/<int:product_id>/reviews', methods=['GET'])
    def red_get_product_reviews(product_id):
        """
        Get product reviews
        VULNERABLE: Returns unsanitized review content (XSS in frontend)
        """
        try:
            conn = get_db()
            cursor = conn.execute('''
                SELECT * FROM reviews 
                WHERE product_id = ?
                ORDER BY created_at DESC
            ''', (product_id,))
            
            reviews = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            # VULNERABLE: No output encoding - reviews can contain XSS payloads
            return jsonify({
                'success': True,
                'reviews': reviews,
                'count': len(reviews)
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/red/shopvuln/reviews/add', methods=['POST'])
    def red_add_review():
        """
        VULNERABLE: Stored XSS - No input sanitization on reviews
        Attack: title = "<script>alert('XSS')</script>"
        Attack: comment = "<img src=x onerror='alert(document.cookie)'>"
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        username = session['username']
        data = request.get_json()
        
        product_id = data.get('product_id')
        rating = int(data.get('rating', 5))
        title = data.get('title', '')
        comment = data.get('comment', '')
        
        if not product_id or rating < 1 or rating > 5:
            return jsonify({
                'success': False,
                'error': 'Invalid product or rating'
            }), 400
        
        try:
            conn = get_db()
            
            # VULNERABLE: No input sanitization - Stored XSS
            cursor = conn.execute('''
                INSERT INTO reviews (product_id, user_id, username, rating, title, comment)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (product_id, user_id, username, rating, title, comment))
            
            review_id = cursor.lastrowid
            
            # Update product rating
            cursor = conn.execute('''
                SELECT AVG(rating) as avg_rating, COUNT(*) as review_count
                FROM reviews WHERE product_id = ?
            ''', (product_id,))
            stats = cursor.fetchone()
            
            conn.execute('''
                UPDATE products 
                SET rating = ?, reviews_count = ?
                WHERE id = ?
            ''', (round(stats['avg_rating'], 1), stats['review_count'], product_id))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Review added successfully',
                'review_id': review_id
            }), 201
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # ============================================================================
    # VULNERABILITY #5: IDOR (Order Access)
    # ============================================================================
    
    @app.route('/api/red/shopvuln/orders', methods=['GET'])
    def red_get_orders():
        """Get user's orders"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        try:
            conn = get_db()
            cursor = conn.execute('''
                SELECT * FROM orders 
                WHERE user_id = ?
                ORDER BY created_at DESC
            ''', (user_id,))
            
            orders = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return jsonify({
                'success': True,
                'orders': orders
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/red/shopvuln/orders/<int:order_id>', methods=['GET'])
    def red_get_order(order_id):
        """
        VULNERABLE: IDOR - No authorization check
        Attack: Change order_id in URL to access other users' orders
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        try:
            conn = get_db()
            
            # VULNERABLE: No ownership verification - IDOR vulnerability
            cursor = conn.execute('SELECT * FROM orders WHERE id = ?', (order_id,))
            order = cursor.fetchone()
            
            if not order:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Order not found'
                }), 404
            
            # Get order items
            cursor = conn.execute('''
                SELECT oi.*, p.name, p.category, p.image
                FROM order_items oi
                JOIN products p ON oi.product_id = p.id
                WHERE oi.order_id = ?
            ''', (order_id,))
            
            items = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            order_dict = dict(order)
            order_dict['items'] = items
            
            return jsonify({
                'success': True,
                'order': order_dict
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # ============================================================================
    # VULNERABILITY #6: PAYMENT BYPASS (Checkout Completion)
    # ============================================================================
    
    @app.route('/api/red/shopvuln/checkout/complete', methods=['POST'])
    def red_complete_checkout():
        """
        VULNERABLE: Payment Bypass - Trusts client-side payment verification
        Attack: Send payment_verified=true without actual payment processing
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        data = request.get_json()
        
        payment_method = data.get('payment_method', 'credit_card')
        # VULNERABLE: Client controls payment verification status
        payment_verified = data.get('payment_verified', False)
        applied_coupons = data.get('applied_coupons', [])
        
        try:
            conn = get_db()
            
            # Get cart items
            cursor = conn.execute('''
                SELECT ci.*, p.name, p.stock
                FROM cart_items ci
                JOIN products p ON ci.product_id = p.id
                WHERE ci.user_id = ?
            ''', (user_id,))
            
            cart_items = [dict(row) for row in cursor.fetchall()]
            
            if not cart_items:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Cart is empty'
                }), 400
            
            # Calculate totals
            subtotal = sum(item['price'] * item['quantity'] for item in cart_items)
            
            # VULNERABLE: Calculate discount from client-provided coupons
            # No validation that coupons were actually applied through proper endpoint
            total_discount = 0
            for coupon_data in applied_coupons:
                if coupon_data.get('discount_type') == 'percentage':
                    total_discount += subtotal * (coupon_data.get('discount_value', 0) / 100)
                else:
                    total_discount += coupon_data.get('discount_value', 0)
            
            shipping = 9.99 if subtotal < 50 else 0
            total = max(0, subtotal - total_discount + shipping)
            
            # Create order
            order_number = generate_order_number()
            
            cursor = conn.execute('''
                INSERT INTO orders (user_id, order_number, status, total, subtotal, discount, shipping, 
                                  payment_method, payment_verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, order_number, 'processing', total, subtotal, total_discount, 
                  shipping, payment_method, payment_verified))  # VULNERABLE: Trusts client
            
            order_id = cursor.lastrowid
            
            # Create order items
            for item in cart_items:
                conn.execute('''
                    INSERT INTO order_items (order_id, product_id, quantity, price)
                    VALUES (?, ?, ?, ?)
                ''', (order_id, item['product_id'], item['quantity'], item['price']))
                
                # Update product stock
                conn.execute(
                    'UPDATE products SET stock = stock - ? WHERE id = ?',
                    (item['quantity'], item['product_id'])
                )
            
            # Record coupon usage (if coupons were applied)
            for coupon_data in applied_coupons:
                coupon_code = coupon_data.get('code')
                if coupon_code:
                    cursor = conn.execute(
                        'SELECT id FROM coupons WHERE code = ?',
                        (coupon_code,)
                    )
                    coupon = cursor.fetchone()
                    if coupon:
                        conn.execute('''
                            INSERT INTO coupon_usages (coupon_id, user_id, order_id)
                            VALUES (?, ?, ?)
                        ''', (coupon['id'], user_id, order_id))
            
            # Clear cart
            conn.execute('DELETE FROM cart_items WHERE user_id = ?', (user_id,))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Order placed successfully',
                'order': {
                    'id': order_id,
                    'order_number': order_number,
                    'total': total,
                    'payment_verified': payment_verified
                }
            }), 201
            
        except Exception as e:
            if conn:
                conn.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # ============================================================================
    # VULNERABILITY #7: RACE CONDITION (Inventory Management)
    # ============================================================================
    
    @app.route('/api/red/shopvuln/checkout/purchase', methods=['POST'])
    def red_purchase_item():
        """
        VULNERABLE: Race condition in inventory check
        Attack: Send multiple concurrent purchase requests for limited stock items
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        data = request.get_json()
        
        product_id = data.get('product_id')
        quantity = int(data.get('quantity', 1))
        
        if not product_id or quantity <= 0:
            return jsonify({
                'success': False,
                'error': 'Invalid product or quantity'
            }), 400
        
        try:
            conn = get_db()
            
            # VULNERABLE: No locking mechanism - Race condition possible
            # Step 1: Check stock (time gap allows concurrent requests)
            cursor = conn.execute(
                'SELECT * FROM products WHERE id = ?',
                (product_id,)
            )
            product = cursor.fetchone()
            
            if not product:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Product not found'
                }), 404
            
            # VULNERABLE: Stock check happens here, but update happens later
            # Multiple requests can pass this check before any update occurs
            if product['stock'] < quantity:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Insufficient stock',
                    'available': product['stock']
                }), 400
            
            # Simulate processing time (makes race condition more obvious)
            time.sleep(0.1)
            
            # Step 2: Deduct stock (VULNERABLE: No transaction isolation)
            conn.execute(
                'UPDATE products SET stock = stock - ? WHERE id = ?',
                (quantity, product_id)
            )
            
            # Calculate price
            total = product['price'] * quantity
            
            # Create order
            order_number = generate_order_number()
            
            cursor = conn.execute('''
                INSERT INTO orders (user_id, order_number, status, total, subtotal, discount, shipping,
                                  payment_method, payment_verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, order_number, 'processing', total, total, 0, 0, 'credit_card', True))
            
            order_id = cursor.lastrowid
            
            # Create order item
            conn.execute('''
                INSERT INTO order_items (order_id, product_id, quantity, price)
                VALUES (?, ?, ?, ?)
            ''', (order_id, product_id, quantity, product['price']))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Purchase successful',
                'order': {
                    'id': order_id,
                    'order_number': order_number,
                    'total': total
                }
            }), 201
            
        except Exception as e:
            if conn:
                conn.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # ============================================================================
    # ADDITIONAL ENDPOINTS
    # ============================================================================
    
    @app.route('/api/red/shopvuln/profile', methods=['GET'])
    def red_get_profile():
        """Get user profile"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        try:
            conn = get_db()
            cursor = conn.execute(
                'SELECT id, username, email, full_name, phone, address, role, created_at FROM shop_users WHERE id = ?',
                (user_id,)
            )
            user = cursor.fetchone()
            conn.close()
            
            if user:
                return jsonify({
                    'success': True,
                    'profile': dict(user)
                }), 200
            else:
                return jsonify({
                    'success': False,
                    'error': 'User not found'
                }), 404
                
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/red/shopvuln/profile', methods=['PUT'])
    def red_update_profile():
        """Update user profile"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        data = request.get_json()
        
        # Only allow updating specific fields
        allowed_fields = ['full_name', 'email', 'phone', 'address']
        updates = []
        values = []
        
        for field in allowed_fields:
            if field in data:
                updates.append(f"{field} = ?")
                values.append(data[field])
        
        if not updates:
            return jsonify({
                'success': False,
                'error': 'No fields to update'
            }), 400
        
        values.append(user_id)
        query = f"UPDATE shop_users SET {', '.join(updates)} WHERE id = ?"
        
        try:
            conn = get_db()
            conn.execute(query, values)
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Profile updated successfully'
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/red/shopvuln/dashboard', methods=['GET'])
    def red_get_dashboard():
        """Get user dashboard data"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        try:
            conn = get_db()
            
            # Get user info
            cursor = conn.execute(
                'SELECT username, full_name, email FROM shop_users WHERE id = ?',
                (user_id,)
            )
            user_info = dict(cursor.fetchone())
            
            # Get recent orders
            cursor = conn.execute('''
                SELECT * FROM orders 
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 5
            ''', (user_id,))
            recent_orders = [dict(row) for row in cursor.fetchall()]
            
            # Get order count
            cursor = conn.execute(
                'SELECT COUNT(*) as count FROM orders WHERE user_id = ?',
                (user_id,)
            )
            order_count = cursor.fetchone()['count']
            
            # Get cart count
            cursor = conn.execute(
                'SELECT COUNT(*) as count FROM cart_items WHERE user_id = ?',
                (user_id,)
            )
            cart_count = cursor.fetchone()['count']
            
            # Get review count
            cursor = conn.execute(
                'SELECT COUNT(*) as count FROM reviews WHERE user_id = ?',
                (user_id,)
            )
            review_count = cursor.fetchone()['count']
            
            conn.close()
            
            return jsonify({
                'success': True,
                'dashboard': {
                    'user': user_info,
                    'recent_orders': recent_orders,
                    'stats': {
                        'total_orders': order_count,
                        'cart_items': cart_count,
                        'reviews_written': review_count
                    }
                }
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/red/shopvuln/stats', methods=['GET'])
    def red_get_stats():
        """Get general statistics (public endpoint)"""
        try:
            conn = get_db()
            
            # Product count
            cursor = conn.execute('SELECT COUNT(*) as count FROM products')
            product_count = cursor.fetchone()['count']
            
            # Category count
            cursor = conn.execute('SELECT COUNT(DISTINCT category) as count FROM products')
            category_count = cursor.fetchone()['count']
            
            # Total orders
            cursor = conn.execute('SELECT COUNT(*) as count FROM orders')
            order_count = cursor.fetchone()['count']
            
            # Total reviews
            cursor = conn.execute('SELECT COUNT(*) as count FROM reviews')
            review_count = cursor.fetchone()['count']
            
            conn.close()
            
            return jsonify({
                'success': True,
                'stats': {
                    'products': product_count,
                    'categories': category_count,
                    'orders': order_count,
                    'reviews': review_count
                }
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    return app


if __name__ == '__main__':
    app = create_red_team_api()
    print("🔴 ShopVuln Red Team API (VULNERABLE) starting...")
    print("⚠️  WARNING: This application contains intentional vulnerabilities")
    print("🔗 Base URL: http://localhost:5001/api/red/shopvuln")
    print("\n📋 Vulnerabilities demonstrated:")
    print("   1. SQL Injection (Product Search)")
    print("   2. Price Manipulation (Shopping Cart)")
    print("   3. Coupon Stacking (Checkout)")
    print("   4. Stored XSS (Product Reviews)")
    print("   5. IDOR (Order Access)")
    print("   6. Payment Bypass (Checkout)")
    print("   7. Race Condition (Inventory)")
    # NOTE: debug=True is INTENTIONALLY enabled for educational purposes
    # This is a VULNERABILITY - allows access to Python debugger
    # NEVER use debug=True in production!
    app.run(debug=True, port=5001)  # nosec - intentional vulnerability
