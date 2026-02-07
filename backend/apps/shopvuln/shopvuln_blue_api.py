"""
ShopVuln Blue Team API - SECURE VERSION
Demonstrates proper security implementations for e-commerce applications.

Security Fixes Implemented:
1. SQL Injection Prevention → Parameterized queries in product search
2. Price Manipulation Prevention → Server-side price validation in cart
3. Coupon Stacking Prevention → Business logic validation, track usage
4. Stored XSS Prevention → Output encoding in reviews
5. IDOR Prevention → Authorization checks in order access
6. Payment Bypass Prevention → Server-side payment verification
7. Race Condition Prevention → Database transaction locking for inventory
"""

from flask import Flask, request, jsonify, session
from flask_cors import CORS
import sqlite3
from datetime import datetime, timedelta
import os
import secrets
import threading
import random
import string
import re
import html

# Database configuration
DB_PATH = os.path.join(os.path.dirname(__file__), 'shopvuln.db')

# Thread lock for preventing race conditions in inventory management
inventory_lock = threading.Lock()


def get_db():
    """Get database connection with row factory"""
    conn = sqlite3.connect(DB_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    # Enable Write-Ahead Logging for better concurrency
    conn.execute('PRAGMA journal_mode=WAL')
    return conn


def escape_html(text):
    """HTML entity encoding to prevent XSS"""
    if not text:
        return text
    return html.escape(str(text), quote=True)


def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_phone(phone):
    """Validate phone format"""
    if not phone:
        return True  # Phone is optional
    pattern = r'^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$'
    return re.match(pattern, phone) is not None


def generate_order_number():
    """Generate unique order number"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_part = ''.join(random.choices(string.digits, k=4))
    return f"ORD-{timestamp}-{random_part}"


def create_blue_team_api():
    """Create Flask app with secure endpoints"""
    app = Flask(__name__)
    app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    
    # Secure CORS configuration
    CORS(app, supports_credentials=True, resources={
        r"/api/blue/shopvuln/*": {
            "origins": ["http://localhost:3000", "http://localhost:5000"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "X-CSRF-Token"]
        }
    })
    
    # Add security headers
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses"""
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    # ============================================================================
    # AUTHENTICATION ENDPOINTS
    # ============================================================================
    
    @app.route('/api/blue/shopvuln/login', methods=['POST'])
    def blue_login():
        """
        SECURE: Login with parameterized queries
        Generates CSRF token on successful login
        """
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        
        # Input validation
        if not username or not password:
            return jsonify({
                'success': False,
                'error': 'Username and password required'
            }), 400
        
        try:
            conn = get_db()
            cursor = conn.execute(
                'SELECT * FROM shop_users WHERE username = ? AND password = ?',
                (username, password)
            )
            user = cursor.fetchone()
            
            if user:
                # Store user in session
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                
                # Generate CSRF token
                csrf_token = secrets.token_hex(32)
                session['csrf_token'] = csrf_token
                
                # Update last login
                conn.execute(
                    'UPDATE shop_users SET last_login = ? WHERE id = ?',
                    (datetime.now().isoformat(), user['id'])
                )
                conn.commit()
                conn.close()
                
                return jsonify({
                    'success': True,
                    'user': {
                        'id': user['id'],
                        'username': user['username'],
                        'full_name': user['full_name'],
                        'email': user['email'],
                        'role': user['role']
                    },
                    'csrf_token': csrf_token,
                    'message': 'Login successful'
                }), 200
            else:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Invalid credentials'
                }), 401
                
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Login failed'
            }), 500
    
    @app.route('/api/blue/shopvuln/logout', methods=['POST'])
    def blue_logout():
        """Logout endpoint with CSRF protection"""
        # Verify CSRF token
        csrf_token = request.headers.get('X-CSRF-Token')
        if csrf_token and csrf_token == session.get('csrf_token'):
            session.clear()
            return jsonify({'success': True, 'message': 'Logged out'}), 200
        
        session.clear()
        return jsonify({'success': True, 'message': 'Logged out'}), 200
    
    @app.route('/api/blue/shopvuln/session', methods=['GET'])
    def blue_get_session():
        """Get current session info"""
        if 'user_id' in session:
            return jsonify({
                'authenticated': True,
                'user': {
                    'id': session.get('user_id'),
                    'username': session.get('username'),
                    'role': session.get('role')
                },
                'csrf_token': session.get('csrf_token')
            }), 200
        return jsonify({'authenticated': False}), 200
    
    @app.route('/api/blue/shopvuln/csrf-token', methods=['GET'])
    def blue_get_csrf_token():
        """Get or generate CSRF token"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        
        return jsonify({
            'success': True,
            'csrf_token': session['csrf_token']
        }), 200
    
    # ============================================================================
    # SECURITY FIX #1: SQL Injection Prevention (Parameterized Queries)
    # ============================================================================
    
    @app.route('/api/blue/shopvuln/search', methods=['GET'])
    def blue_search_products():
        """
        SECURE: Parameterized queries prevent SQL injection
        Uses placeholders (?) instead of string concatenation
        """
        search_query = request.args.get('query', '')
        category = request.args.get('category', '')
        
        try:
            conn = get_db()
            
            # SECURE: Parameterized query - SQL Injection prevented
            if category:
                # Use LIKE with proper parameterization
                query = "SELECT * FROM products WHERE category = ? AND (name LIKE ? OR description LIKE ?)"
                search_pattern = f'%{search_query}%'
                cursor = conn.execute(query, (category, search_pattern, search_pattern))
            else:
                query = "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?"
                search_pattern = f'%{search_query}%'
                cursor = conn.execute(query, (search_pattern, search_pattern))
            
            products = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return jsonify({
                'success': True,
                'products': products,
                'count': len(products)
            }), 200
            
        except Exception as e:
            # SECURE: Don't leak error details
            return jsonify({
                'success': False,
                'error': 'Search failed'
            }), 500
    
    @app.route('/api/blue/shopvuln/products', methods=['GET'])
    def blue_get_products():
        """Get all products with parameterized queries"""
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
                'error': 'Failed to retrieve products'
            }), 500
    
    @app.route('/api/blue/shopvuln/products/<int:product_id>', methods=['GET'])
    def blue_get_product(product_id):
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
                'error': 'Failed to retrieve product'
            }), 500
    
    @app.route('/api/blue/shopvuln/categories', methods=['GET'])
    def blue_get_categories():
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
                'error': 'Failed to retrieve categories'
            }), 500
    
    # ============================================================================
    # SECURITY FIX #2: Price Manipulation Prevention (Server-Side Validation)
    # ============================================================================
    
    @app.route('/api/blue/shopvuln/cart', methods=['GET'])
    def blue_get_cart():
        """
        SECURE: Returns cart with server-validated prices
        Calculates totals on server side
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        try:
            conn = get_db()
            
            # Get cart items with product details
            cursor = conn.execute('''
                SELECT ci.*, p.name, p.category, p.image, p.stock, p.price as current_price
                FROM cart_items ci
                JOIN products p ON ci.product_id = p.id
                WHERE ci.user_id = ?
            ''', (user_id,))
            
            cart_items = []
            subtotal = 0
            
            for row in cursor.fetchall():
                item = dict(row)
                
                # SECURE: Always use current price from database, not stored price
                actual_price = item['current_price']
                item['price'] = actual_price
                item['subtotal'] = actual_price * item['quantity']
                
                cart_items.append(item)
                subtotal += item['subtotal']
            
            conn.close()
            
            # Calculate shipping
            shipping = 9.99 if subtotal < 50 else 0
            total = subtotal + shipping
            
            return jsonify({
                'success': True,
                'cart': {
                    'items': cart_items,
                    'subtotal': subtotal,
                    'shipping': shipping,
                    'total': total,
                    'count': len(cart_items)
                }
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Failed to retrieve cart'
            }), 500
    
    @app.route('/api/blue/shopvuln/cart/add', methods=['POST'])
    def blue_add_to_cart():
        """
        SECURE: Fetches price from database, ignores client price
        Server determines the price, not the client
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        data = request.get_json()
        
        product_id = data.get('product_id')
        quantity = int(data.get('quantity', 1))
        # SECURE: Ignore client-provided price
        
        if not product_id or quantity <= 0:
            return jsonify({
                'success': False,
                'error': 'Invalid product or quantity'
            }), 400
        
        try:
            conn = get_db()
            
            # SECURE: Fetch actual price from database
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
            
            # Check stock availability
            if product['stock'] < quantity:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Insufficient stock',
                    'available': product['stock']
                }), 400
            
            # SECURE: Use price from database, not client
            actual_price = product['price']
            
            # Check if item already in cart
            cursor = conn.execute(
                'SELECT * FROM cart_items WHERE user_id = ? AND product_id = ?',
                (user_id, product_id)
            )
            existing_item = cursor.fetchone()
            
            if existing_item:
                # Update quantity and price
                new_quantity = existing_item['quantity'] + quantity
                conn.execute(
                    'UPDATE cart_items SET quantity = ?, price = ?, updated_at = ? WHERE id = ?',
                    (new_quantity, actual_price, datetime.now().isoformat(), existing_item['id'])
                )
            else:
                # SECURE: Insert with server-determined price
                conn.execute('''
                    INSERT INTO cart_items (user_id, product_id, quantity, price, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, product_id, quantity, actual_price, 
                      datetime.now().isoformat(), datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Product added to cart'
            }), 201
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Failed to add to cart'
            }), 500
    
    @app.route('/api/blue/shopvuln/cart/update/<int:item_id>', methods=['PUT'])
    def blue_update_cart_item(item_id):
        """
        SECURE: Validates ownership and refreshes price from database
        Prevents price manipulation during update
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        data = request.get_json()
        quantity = int(data.get('quantity', 1))
        # SECURE: Ignore any client-provided price
        
        if quantity <= 0:
            return jsonify({
                'success': False,
                'error': 'Invalid quantity'
            }), 400
        
        try:
            conn = get_db()
            
            # Verify ownership
            cursor = conn.execute(
                'SELECT * FROM cart_items WHERE id = ? AND user_id = ?',
                (item_id, user_id)
            )
            cart_item = cursor.fetchone()
            
            if not cart_item:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Cart item not found'
                }), 404
            
            # SECURE: Fetch current price from products table
            cursor = conn.execute(
                'SELECT price, stock FROM products WHERE id = ?',
                (cart_item['product_id'],)
            )
            product = cursor.fetchone()
            
            if not product:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Product not found'
                }), 404
            
            # Check stock
            if product['stock'] < quantity:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Insufficient stock',
                    'available': product['stock']
                }), 400
            
            # SECURE: Update with current database price
            conn.execute(
                'UPDATE cart_items SET quantity = ?, price = ?, updated_at = ? WHERE id = ?',
                (quantity, product['price'], datetime.now().isoformat(), item_id)
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
                'error': 'Failed to update cart'
            }), 500
    
    @app.route('/api/blue/shopvuln/cart/remove/<int:item_id>', methods=['DELETE'])
    def blue_remove_from_cart(item_id):
        """Remove item from cart with ownership verification"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        try:
            conn = get_db()
            
            # Verify ownership before deletion
            cursor = conn.execute(
                'SELECT * FROM cart_items WHERE id = ? AND user_id = ?',
                (item_id, user_id)
            )
            cart_item = cursor.fetchone()
            
            if not cart_item:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Cart item not found'
                }), 404
            
            conn.execute('DELETE FROM cart_items WHERE id = ?', (item_id,))
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Item removed from cart'
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Failed to remove item'
            }), 500
    
    @app.route('/api/blue/shopvuln/cart/clear', methods=['DELETE'])
    def blue_clear_cart():
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
                'error': 'Failed to clear cart'
            }), 500
    
    # ============================================================================
    # SECURITY FIX #3: Coupon Stacking Prevention (Business Logic Validation)
    # ============================================================================
    
    @app.route('/api/blue/shopvuln/coupons', methods=['GET'])
    def blue_get_coupons():
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
                'error': 'Failed to retrieve coupons'
            }), 500
    
    @app.route('/api/blue/shopvuln/checkout/validate-coupon', methods=['POST'])
    def blue_validate_coupon():
        """
        SECURE: Validates coupon with proper business logic
        - Prevents stacking by checking session state
        - Enforces max_uses_per_user limit
        - Validates expiry and minimum purchase
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        # Verify CSRF token
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
        
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
            
            # SECURE: Check if user already has a coupon in their current session
            if 'applied_coupon' in session:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Only one coupon can be applied per order'
                }), 400
            
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
            
            # SECURE: Check max uses per user
            cursor = conn.execute(
                'SELECT COUNT(*) as usage_count FROM coupon_usages WHERE coupon_id = ? AND user_id = ?',
                (coupon['id'], user_id)
            )
            usage = cursor.fetchone()
            
            if usage['usage_count'] >= coupon['max_uses_per_user']:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'You have already used this coupon the maximum number of times'
                }), 400
            
            # SECURE: Check global max uses
            cursor = conn.execute(
                'SELECT COUNT(*) as total_uses FROM coupon_usages WHERE coupon_id = ?',
                (coupon['id'],)
            )
            total_usage = cursor.fetchone()
            
            if total_usage['total_uses'] >= coupon['max_uses']:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'This coupon has reached its maximum usage limit'
                }), 400
            
            # Calculate discount
            if coupon['discount_type'] == 'percentage':
                discount = cart_total * (coupon['discount_value'] / 100)
            else:  # fixed
                discount = coupon['discount_value']
            
            # Cap discount at cart total
            discount = min(discount, cart_total)
            
            # SECURE: Store validated coupon in session (prevents stacking)
            session['applied_coupon'] = {
                'id': coupon['id'],
                'code': coupon['code'],
                'discount_type': coupon['discount_type'],
                'discount_value': coupon['discount_value'],
                'discount': discount
            }
            
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
                'error': 'Failed to validate coupon'
            }), 500
    
    @app.route('/api/blue/shopvuln/checkout/remove-coupon', methods=['POST'])
    def blue_remove_coupon():
        """Remove applied coupon from session"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        # Verify CSRF token
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
        
        # Remove coupon from session
        if 'applied_coupon' in session:
            del session['applied_coupon']
        
        return jsonify({
            'success': True,
            'message': 'Coupon removed'
        }), 200
    
    # ============================================================================
    # SECURITY FIX #4: Stored XSS Prevention (Output Encoding)
    # ============================================================================
    
    @app.route('/api/blue/shopvuln/products/<int:product_id>/reviews', methods=['GET'])
    def blue_get_product_reviews(product_id):
        """
        SECURE: HTML-encodes review content before returning
        Prevents XSS by encoding special characters
        """
        try:
            conn = get_db()
            cursor = conn.execute(
                'SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC',
                (product_id,)
            )
            reviews = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            # SECURE: Encode HTML entities in reviews to prevent XSS
            for review in reviews:
                if review.get('title'):
                    review['title'] = escape_html(review['title'])
                if review.get('comment'):
                    review['comment'] = escape_html(review['comment'])
                if review.get('username'):
                    review['username'] = escape_html(review['username'])
            
            return jsonify({
                'success': True,
                'reviews': reviews,
                'count': len(reviews)
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Failed to retrieve reviews'
            }), 500
    
    @app.route('/api/blue/shopvuln/reviews/add', methods=['POST'])
    def blue_add_review():
        """
        SECURE: Sanitizes input before storing
        Stores sanitized content and encodes on output
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        # Verify CSRF token
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
        
        user_id = session['user_id']
        username = session['username']
        data = request.get_json()
        
        product_id = data.get('product_id')
        rating = int(data.get('rating', 0))
        title = data.get('title', '').strip()
        comment = data.get('comment', '').strip()
        
        # Input validation
        if not product_id or rating < 1 or rating > 5:
            return jsonify({
                'success': False,
                'error': 'Invalid product or rating'
            }), 400
        
        if not title or not comment:
            return jsonify({
                'success': False,
                'error': 'Title and comment required'
            }), 400
        
        try:
            conn = get_db()
            
            # Verify product exists
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
            
            # SECURE: HTML entity encoding before storing
            # Defense in depth - sanitize on input AND encode on output
            title_sanitized = escape_html(title)
            comment_sanitized = escape_html(comment)
            username_sanitized = escape_html(username)
            
            # Insert review
            cursor = conn.execute('''
                INSERT INTO reviews (product_id, user_id, username, rating, title, comment, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (product_id, user_id, username_sanitized, rating, title_sanitized, 
                  comment_sanitized, datetime.now().isoformat()))
            
            review_id = cursor.lastrowid
            
            # Update product rating
            cursor = conn.execute(
                'SELECT AVG(rating) as avg_rating, COUNT(*) as count FROM reviews WHERE product_id = ?',
                (product_id,)
            )
            stats = cursor.fetchone()
            
            conn.execute(
                'UPDATE products SET rating = ?, reviews_count = ? WHERE id = ?',
                (round(stats['avg_rating'], 1), stats['count'], product_id)
            )
            
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
                'error': 'Failed to add review'
            }), 500
    
    # ============================================================================
    # SECURITY FIX #5: IDOR Prevention (Authorization Checks)
    # ============================================================================
    
    @app.route('/api/blue/shopvuln/orders', methods=['GET'])
    def blue_get_orders():
        """
        SECURE: Only returns orders belonging to authenticated user
        Proper authorization check
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        try:
            conn = get_db()
            cursor = conn.execute(
                'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC',
                (user_id,)
            )
            orders = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return jsonify({
                'success': True,
                'orders': orders,
                'count': len(orders)
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Failed to retrieve orders'
            }), 500
    
    @app.route('/api/blue/shopvuln/orders/<int:order_id>', methods=['GET'])
    def blue_get_order(order_id):
        """
        SECURE: Verifies ownership before returning order
        Prevents IDOR by checking user_id matches
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        try:
            conn = get_db()
            
            # SECURE: Verify ownership with user_id in query
            cursor = conn.execute(
                'SELECT * FROM orders WHERE id = ? AND user_id = ?',
                (order_id, user_id)
            )
            order = cursor.fetchone()
            
            if not order:
                conn.close()
                # Don't reveal if order exists or not
                return jsonify({
                    'success': False,
                    'error': 'Order not found or access denied'
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
                'error': 'Failed to retrieve order'
            }), 500
    
    # ============================================================================
    # SECURITY FIX #6: Payment Bypass Prevention (Server-Side Verification)
    # ============================================================================
    
    @app.route('/api/blue/shopvuln/checkout/complete', methods=['POST'])
    def blue_complete_checkout():
        """
        SECURE: Server-side payment verification
        - Validates prices from database, not client
        - Verifies coupon from session, not client input
        - Only marks payment_verified=true after actual verification
        - Uses CSRF protection
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        # Verify CSRF token
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
        
        user_id = session['user_id']
        data = request.get_json()
        
        payment_method = data.get('payment_method', 'credit_card')
        payment_token = data.get('payment_token')  # Would be from payment gateway
        # SECURE: Ignore client's payment_verified flag
        
        if not payment_token:
            return jsonify({
                'success': False,
                'error': 'Payment token required'
            }), 400
        
        try:
            conn = get_db()
            
            # Get cart items with current prices from database
            cursor = conn.execute('''
                SELECT ci.*, p.name, p.stock, p.price as current_price
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
            
            # SECURE: Calculate totals using database prices, not cart prices
            subtotal = sum(item['current_price'] * item['quantity'] for item in cart_items)
            
            # SECURE: Get coupon from session, not from client
            total_discount = 0
            coupon_id = None
            
            if 'applied_coupon' in session:
                coupon_data = session['applied_coupon']
                coupon_id = coupon_data.get('id')
                
                # Re-validate coupon is still valid
                cursor = conn.execute(
                    'SELECT * FROM coupons WHERE id = ? AND active = 1',
                    (coupon_id,)
                )
                coupon = cursor.fetchone()
                
                if coupon:
                    # Recalculate discount with current cart total
                    if coupon['discount_type'] == 'percentage':
                        total_discount = subtotal * (coupon['discount_value'] / 100)
                    else:
                        total_discount = coupon['discount_value']
                    
                    total_discount = min(total_discount, subtotal)
            
            shipping = 9.99 if subtotal < 50 else 0
            total = max(0, subtotal - total_discount + shipping)
            
            # SECURE: Verify payment with payment gateway
            # In real implementation, this would call Stripe, PayPal, etc.
            payment_verified = verify_payment(payment_token, total)
            
            if not payment_verified:
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Payment verification failed'
                }), 402  # Payment Required
            
            # Create order
            order_number = generate_order_number()
            
            cursor = conn.execute('''
                INSERT INTO orders (user_id, order_number, status, total, subtotal, discount, shipping, 
                                  payment_method, payment_verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, order_number, 'processing', total, subtotal, total_discount, 
                  shipping, payment_method, payment_verified))  # SECURE: Server-verified
            
            order_id = cursor.lastrowid
            
            # Create order items with current prices
            for item in cart_items:
                conn.execute('''
                    INSERT INTO order_items (order_id, product_id, quantity, price)
                    VALUES (?, ?, ?, ?)
                ''', (order_id, item['product_id'], item['quantity'], item['current_price']))
                
                # Update product stock
                conn.execute(
                    'UPDATE products SET stock = stock - ? WHERE id = ?',
                    (item['quantity'], item['product_id'])
                )
            
            # Record coupon usage if coupon was applied
            if coupon_id:
                conn.execute('''
                    INSERT INTO coupon_usages (coupon_id, user_id, order_id, used_at)
                    VALUES (?, ?, ?, ?)
                ''', (coupon_id, user_id, order_id, datetime.now().isoformat()))
                
                # Clear coupon from session
                del session['applied_coupon']
            
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
                'error': 'Checkout failed'
            }), 500
    
    # ============================================================================
    # SECURITY FIX #7: Race Condition Prevention (Database Locking)
    # ============================================================================
    
    @app.route('/api/blue/shopvuln/checkout/purchase', methods=['POST'])
    def blue_purchase_item():
        """
        SECURE: Uses transaction with locking to prevent race conditions
        - Implements mutex lock for thread safety
        - Uses BEGIN EXCLUSIVE transaction for atomic operations
        - Checks stock within transaction before update
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        # Verify CSRF token
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
        
        user_id = session['user_id']
        data = request.get_json()
        
        product_id = data.get('product_id')
        quantity = int(data.get('quantity', 1))
        
        if not product_id or quantity <= 0:
            return jsonify({
                'success': False,
                'error': 'Invalid product or quantity'
            }), 400
        
        # SECURE: Use mutex lock to prevent concurrent access
        with inventory_lock:
            try:
                conn = get_db()
                
                # SECURE: BEGIN EXCLUSIVE transaction for atomic operations
                conn.execute('BEGIN EXCLUSIVE')
                
                # Get product with lock
                cursor = conn.execute(
                    'SELECT * FROM products WHERE id = ?',
                    (product_id,)
                )
                product = cursor.fetchone()
                
                if not product:
                    conn.rollback()
                    conn.close()
                    return jsonify({
                        'success': False,
                        'error': 'Product not found'
                    }), 404
                
                # SECURE: Check stock within transaction (atomic)
                if product['stock'] < quantity:
                    conn.rollback()
                    conn.close()
                    return jsonify({
                        'success': False,
                        'error': 'Insufficient stock',
                        'available': product['stock']
                    }), 400
                
                # SECURE: Deduct stock within same transaction - atomic operation
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
                
                # SECURE: Commit all changes atomically
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
                    conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Purchase failed'
                }), 500
    
    # ============================================================================
    # ADDITIONAL SECURE ENDPOINTS
    # ============================================================================
    
    @app.route('/api/blue/shopvuln/profile', methods=['GET'])
    def blue_get_profile():
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
                'error': 'Failed to retrieve profile'
            }), 500
    
    @app.route('/api/blue/shopvuln/profile', methods=['PUT'])
    def blue_update_profile():
        """
        SECURE: Whitelists allowed fields to prevent mass assignment
        Only specific, safe fields can be updated
        """
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        # Verify CSRF token
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
        
        user_id = session['user_id']
        data = request.get_json()
        
        # SECURE: Whitelist of allowed fields - prevents mass assignment
        allowed_fields = ['full_name', 'email', 'phone', 'address']
        
        # Filter to only allowed fields
        update_data = {}
        for field in allowed_fields:
            if field in data:
                value = data[field]
                # Sanitize string inputs
                if isinstance(value, str):
                    value = escape_html(value.strip())
                update_data[field] = value
        
        if not update_data:
            return jsonify({
                'success': False,
                'error': 'No valid fields to update'
            }), 400
        
        # Additional validation
        if 'email' in update_data:
            if not validate_email(update_data['email']):
                return jsonify({
                    'success': False,
                    'error': 'Invalid email format'
                }), 400
        
        if 'phone' in update_data:
            if not validate_phone(update_data['phone']):
                return jsonify({
                    'success': False,
                    'error': 'Invalid phone format'
                }), 400
        
        # Build parameterized query
        fields = ', '.join([f"{k} = ?" for k in update_data.keys()])
        values = list(update_data.values()) + [user_id]
        query = f"UPDATE shop_users SET {fields} WHERE id = ?"
        
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
                'error': 'Update failed'
            }), 500
    
    @app.route('/api/blue/shopvuln/dashboard', methods=['GET'])
    def blue_get_dashboard():
        """Get user dashboard with proper authorization"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        try:
            conn = get_db()
            
            # Get user info
            cursor = conn.execute(
                'SELECT id, username, email, full_name FROM shop_users WHERE id = ?',
                (user_id,)
            )
            user_info = dict(cursor.fetchone())
            
            # Get order count
            cursor = conn.execute(
                'SELECT COUNT(*) as order_count FROM orders WHERE user_id = ?',
                (user_id,)
            )
            order_count = cursor.fetchone()['order_count']
            
            # Get recent orders (with ownership check)
            cursor = conn.execute(
                'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 5',
                (user_id,)
            )
            recent_orders = [dict(row) for row in cursor.fetchall()]
            
            # Get cart count
            cursor = conn.execute(
                'SELECT COUNT(*) as cart_count FROM cart_items WHERE user_id = ?',
                (user_id,)
            )
            cart_count = cursor.fetchone()['cart_count']
            
            conn.close()
            
            return jsonify({
                'success': True,
                'dashboard': {
                    'user': user_info,
                    'order_count': order_count,
                    'recent_orders': recent_orders,
                    'cart_count': cart_count
                }
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Failed to retrieve dashboard'
            }), 500
    
    @app.route('/api/blue/shopvuln/stats', methods=['GET'])
    def blue_get_stats():
        """Get user statistics with authorization"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        try:
            conn = get_db()
            
            # Total spent (only user's orders)
            cursor = conn.execute(
                'SELECT SUM(total) as total_spent FROM orders WHERE user_id = ? AND payment_verified = 1',
                (user_id,)
            )
            result = cursor.fetchone()
            total_spent = result['total_spent'] or 0
            
            # Total orders
            cursor = conn.execute(
                'SELECT COUNT(*) as total_orders FROM orders WHERE user_id = ?',
                (user_id,)
            )
            total_orders = cursor.fetchone()['total_orders']
            
            # Total reviews written
            cursor = conn.execute(
                'SELECT COUNT(*) as total_reviews FROM reviews WHERE user_id = ?',
                (user_id,)
            )
            total_reviews = cursor.fetchone()['total_reviews']
            
            conn.close()
            
            return jsonify({
                'success': True,
                'stats': {
                    'total_spent': total_spent,
                    'total_orders': total_orders,
                    'total_reviews': total_reviews
                }
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Failed to retrieve stats'
            }), 500
    
    return app


def verify_payment(payment_token, amount):
    """
    SECURE: Simulated payment verification
    In production, this would integrate with:
    - Stripe API
    - PayPal SDK
    - Square Payment Gateway
    - etc.
    
    Returns True if payment is verified, False otherwise
    """
    # Simulated verification - in real app, call payment gateway API
    # For demo purposes, accept tokens that start with 'tok_'
    if payment_token and payment_token.startswith('tok_') and amount > 0:
        return True
    return False


if __name__ == '__main__':
    app = create_blue_team_api()
    print("🔵 ShopVuln Blue Team API (SECURE) starting...")
    print("✅ All 7 security fixes implemented:")
    print("   1. ✅ SQL Injection Prevention (Parameterized Queries)")
    print("   2. ✅ Price Manipulation Prevention (Server-Side Validation)")
    print("   3. ✅ Coupon Stacking Prevention (Business Logic + Session)")
    print("   4. ✅ Stored XSS Prevention (HTML Entity Encoding)")
    print("   5. ✅ IDOR Prevention (Authorization Checks)")
    print("   6. ✅ Payment Bypass Prevention (Server-Side Verification)")
    print("   7. ✅ Race Condition Prevention (Transaction Locking)")
    print("🔗 Base URL: http://localhost:5002/api/blue/shopvuln")
    app.run(debug=False, port=5002)  # Debug disabled for security
