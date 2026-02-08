"""
ShopVuln Seed Data
Populates database with realistic e-commerce data
"""

from datetime import datetime, timedelta
from .database import get_session, init_database
from .models import ShopUser, Product, Review, Order, OrderItem, Coupon, CouponUsage, CartItem


def seed_database():
    """Seed database with realistic e-commerce data"""
    
    # Initialize database first
    init_database()
    session = get_session()
    
    print("\n📦 Seeding database with sample data...")
    
    # ========== Users ==========
    users_data = [
        {
            'username': 'alice',
            'password': 'password123',  # In real app, this would be hashed
            'email': 'alice@shop.com',
            'full_name': 'Alice Johnson',
            'phone': '555-0101',
            'address': '123 Main St, New York, NY 10001',
            'role': 'user'
        },
        {
            'username': 'bob',
            'password': 'securepass456',
            'email': 'bob@shop.com',
            'full_name': 'Bob Smith',
            'phone': '555-0102',
            'address': '456 Oak Ave, Los Angeles, CA 90001',
            'role': 'user'
        },
        {
            'username': 'admin',
            'password': 'admin123',
            'email': 'admin@shop.com',
            'full_name': 'Admin User',
            'phone': '555-0100',
            'address': '789 Admin Blvd, Seattle, WA 98101',
            'role': 'admin'
        },
        {
            'username': 'carol',
            'password': 'carol789',
            'email': 'carol@shop.com',
            'full_name': 'Carol Davis',
            'phone': '555-0103',
            'address': '321 Pine St, Chicago, IL 60601',
            'role': 'user'
        }
    ]
    
    users = []
    for user_data in users_data:
        user = ShopUser(**user_data)
        users.append(user)
        session.add(user)
    
    session.commit()
    print(f"✅ Created {len(users)} users")
    
    # ========== Products ==========
    products_data = [
        {
            'name': 'UltraBook Pro X1',
            'category': 'Laptops',
            'price': 1299.99,
            'description': 'High-performance laptop with 16GB RAM, 512GB SSD, Intel i7 processor, 14-inch 4K display',
            'stock': 45,
            'image': 'laptop-1.jpg',
            'rating': 4.5,
            'reviews_count': 127
        },
        {
            'name': 'Wireless Ergonomic Mouse',
            'category': 'Accessories',
            'price': 29.99,
            'description': 'Comfortable wireless mouse with 6 programmable buttons, 2400 DPI, ergonomic design',
            'stock': 150,
            'image': 'mouse-1.jpg',
            'rating': 4.2,
            'reviews_count': 89
        },
        {
            'name': 'RGB Mechanical Keyboard',
            'category': 'Accessories',
            'price': 89.99,
            'description': 'Cherry MX switches, customizable RGB lighting, aluminum frame, USB-C connection',
            'stock': 80,
            'image': 'keyboard-1.jpg',
            'rating': 4.7,
            'reviews_count': 203
        },
        {
            'name': '4K Ultra HD Monitor 27"',
            'category': 'Monitors',
            'price': 449.99,
            'description': '4K resolution, IPS panel, 60Hz refresh rate, HDR support, VESA mountable',
            'stock': 30,
            'image': 'monitor-1.jpg',
            'rating': 4.6,
            'reviews_count': 156
        },
        {
            'name': 'USB-C Hub 7-in-1',
            'category': 'Accessories',
            'price': 49.99,
            'description': '7 ports including HDMI, USB 3.0, SD card reader, ethernet, perfect for laptops',
            'stock': 200,
            'image': 'hub-1.jpg',
            'rating': 4.3,
            'reviews_count': 67
        },
        {
            'name': 'Wireless Headphones',
            'category': 'Audio',
            'price': 159.99,
            'description': 'Active noise cancellation, 30-hour battery life, premium sound quality, foldable design',
            'stock': 60,
            'image': 'headphones-1.jpg',
            'rating': 4.8,
            'reviews_count': 342
        },
        {
            'name': 'External SSD 1TB',
            'category': 'Storage',
            'price': 129.99,
            'description': 'Portable SSD with 1050 MB/s read speeds, USB 3.2, shock-resistant, compact design',
            'stock': 95,
            'image': 'ssd-1.jpg',
            'rating': 4.5,
            'reviews_count': 78
        },
        {
            'name': 'Gaming Mouse Pad XL',
            'category': 'Accessories',
            'price': 24.99,
            'description': 'Extended size, non-slip rubber base, RGB lighting, smooth surface for precision',
            'stock': 120,
            'image': 'mousepad-1.jpg',
            'rating': 4.1,
            'reviews_count': 45
        },
        {
            'name': 'Webcam 1080p HD',
            'category': 'Accessories',
            'price': 79.99,
            'description': 'Full HD 1080p, autofocus, built-in microphone, works with all video conferencing apps',
            'stock': 70,
            'image': 'webcam-1.jpg',
            'rating': 4.4,
            'reviews_count': 112
        },
        {
            'name': 'Portable Charger 20000mAh',
            'category': 'Accessories',
            'price': 39.99,
            'description': 'High-capacity power bank with fast charging, dual USB ports, LED battery indicator',
            'stock': 140,
            'image': 'charger-1.jpg',
            'rating': 4.3,
            'reviews_count': 234
        },
        {
            'name': 'Wireless Presenter',
            'category': 'Accessories',
            'price': 34.99,
            'description': 'Laser pointer, wireless presenter with USB receiver, up to 100ft range',
            'stock': 85,
            'image': 'presenter-1.jpg',
            'rating': 4.2,
            'reviews_count': 56
        },
        {
            'name': 'Desktop Speakers',
            'category': 'Audio',
            'price': 69.99,
            'description': 'Stereo speakers with subwoofer, 2.1 channel, USB powered, great for music and gaming',
            'stock': 65,
            'image': 'speakers-1.jpg',
            'rating': 4.4,
            'reviews_count': 89
        },
        {
            'name': 'Laptop Stand Aluminum',
            'category': 'Accessories',
            'price': 44.99,
            'description': 'Adjustable laptop stand, ergonomic design, ventilated cooling, fits 10-17 inch laptops',
            'stock': 110,
            'image': 'stand-1.jpg',
            'rating': 4.6,
            'reviews_count': 134
        },
        {
            'name': 'USB Flash Drive 128GB',
            'category': 'Storage',
            'price': 19.99,
            'description': 'High-speed USB 3.0 flash drive, 128GB capacity, keychain design, compact and durable',
            'stock': 250,
            'image': 'usb-1.jpg',
            'rating': 4.1,
            'reviews_count': 312
        },
        {
            'name': 'Wireless Earbuds',
            'category': 'Audio',
            'price': 89.99,
            'description': 'True wireless earbuds with charging case, 24hr battery life, water-resistant IPX4',
            'stock': 90,
            'image': 'earbuds-1.jpg',
            'rating': 4.5,
            'reviews_count': 267
        },
        {
            'name': 'HDMI Cable 6ft',
            'category': 'Accessories',
            'price': 12.99,
            'description': '4K HDMI 2.0 cable, gold-plated connectors, supports 60Hz, perfect for gaming and streaming',
            'stock': 300,
            'image': 'hdmi-1.jpg',
            'rating': 4.3,
            'reviews_count': 423
        },
        {
            'name': 'Laptop Backpack',
            'category': 'Accessories',
            'price': 54.99,
            'description': 'Travel-friendly laptop backpack, fits 15.6 inch laptop, USB charging port, water-resistant',
            'stock': 75,
            'image': 'backpack-1.jpg',
            'rating': 4.7,
            'reviews_count': 189
        },
        {
            'name': 'Graphics Tablet',
            'category': 'Accessories',
            'price': 79.99,
            'description': 'Digital drawing tablet, 8192 pressure levels, battery-free pen, perfect for artists',
            'stock': 50,
            'image': 'tablet-1.jpg',
            'rating': 4.5,
            'reviews_count': 97
        },
        {
            'name': 'Smart Watch',
            'category': 'Wearables',
            'price': 199.99,
            'description': 'Fitness tracker smartwatch, heart rate monitor, GPS, waterproof, 7-day battery',
            'stock': 55,
            'image': 'watch-1.jpg',
            'rating': 4.6,
            'reviews_count': 178
        },
        {
            'name': 'Desk Lamp LED',
            'category': 'Accessories',
            'price': 39.99,
            'description': 'LED desk lamp with USB charging port, adjustable brightness, eye-care technology',
            'stock': 95,
            'image': 'lamp-1.jpg',
            'rating': 4.4,
            'reviews_count': 145
        }
    ]
    
    products = []
    for product_data in products_data:
        product = Product(**product_data)
        products.append(product)
        session.add(product)
    
    session.commit()
    print(f"✅ Created {len(products)} products")
    
    # ========== Reviews ==========
    reviews_data = [
        {
            'product_id': 1,
            'user_id': 1,
            'username': 'alice',
            'rating': 5,
            'title': 'Excellent laptop!',
            'comment': 'Best purchase I made this year. Fast and reliable.',
            'created_at': datetime.now() - timedelta(days=15)
        },
        {
            'product_id': 1,
            'user_id': 2,
            'username': 'bob',
            'rating': 4,
            'title': 'Great performance',
            'comment': 'Really fast, but battery life could be better.',
            'created_at': datetime.now() - timedelta(days=10)
        },
        {
            'product_id': 3,
            'user_id': 1,
            'username': 'alice',
            'rating': 5,
            'title': 'Amazing keyboard',
            'comment': 'Cherry MX switches feel incredible. RGB is beautiful!',
            'created_at': datetime.now() - timedelta(days=5)
        },
        {
            'product_id': 6,
            'user_id': 4,
            'username': 'carol',
            'rating': 5,
            'title': 'Best headphones ever',
            'comment': 'The noise cancellation is phenomenal. Perfect for work and travel.',
            'created_at': datetime.now() - timedelta(days=8)
        },
        {
            'product_id': 4,
            'user_id': 2,
            'username': 'bob',
            'rating': 5,
            'title': 'Crystal clear display',
            'comment': '4K quality is outstanding. Colors are vibrant and accurate.',
            'created_at': datetime.now() - timedelta(days=12)
        },
        {
            'product_id': 7,
            'user_id': 4,
            'username': 'carol',
            'rating': 4,
            'title': 'Fast and reliable',
            'comment': 'Transfer speeds are great. Worth the investment.',
            'created_at': datetime.now() - timedelta(days=6)
        },
        {
            'product_id': 2,
            'user_id': 1,
            'username': 'alice',
            'rating': 4,
            'title': 'Comfortable mouse',
            'comment': 'Very ergonomic, fits my hand perfectly. Buttons are responsive.',
            'created_at': datetime.now() - timedelta(days=3)
        },
        {
            'product_id': 15,
            'user_id': 2,
            'username': 'bob',
            'rating': 5,
            'title': 'Love these earbuds',
            'comment': 'Sound quality is excellent and battery lasts all day.',
            'created_at': datetime.now() - timedelta(days=2)
        }
    ]
    
    reviews = []
    for review_data in reviews_data:
        review = Review(**review_data)
        reviews.append(review)
        session.add(review)
    
    session.commit()
    print(f"✅ Created {len(reviews)} reviews")
    
    # ========== Coupons ==========
    coupons_data = [
        {
            'code': 'SAVE20',
            'discount_type': 'percentage',
            'discount_value': 20,
            'min_purchase': 100.00,
            'max_uses': 1000,
            'max_uses_per_user': 1,
            'valid_from': datetime(2024, 11, 1),
            'valid_until': datetime(2024, 12, 31),
            'active': True
        },
        {
            'code': 'WELCOME10',
            'discount_type': 'percentage',
            'discount_value': 10,
            'min_purchase': 50.00,
            'max_uses': 1000,
            'max_uses_per_user': 1,
            'valid_from': datetime(2024, 1, 1),
            'valid_until': datetime(2024, 12, 31),
            'active': True
        },
        {
            'code': 'FREESHIP',
            'discount_type': 'fixed',
            'discount_value': 9.99,
            'min_purchase': 75.00,
            'max_uses': 500,
            'max_uses_per_user': 3,
            'valid_from': datetime(2024, 11, 1),
            'valid_until': datetime(2024, 12, 31),
            'active': True
        },
        {
            'code': 'BLACKFRIDAY50',
            'discount_type': 'percentage',
            'discount_value': 50,
            'min_purchase': 200.00,
            'max_uses': 100,
            'max_uses_per_user': 1,
            'valid_from': datetime(2024, 11, 29),
            'valid_until': datetime(2024, 11, 30),
            'active': True
        }
    ]
    
    coupons = []
    for coupon_data in coupons_data:
        coupon = Coupon(**coupon_data)
        coupons.append(coupon)
        session.add(coupon)
    
    session.commit()
    print(f"✅ Created {len(coupons)} coupons")
    
    # ========== Orders ==========
    orders_data = [
        {
            'user_id': 1,
            'order_number': 'ORD-2024-001',
            'status': 'delivered',
            'total': 1329.98,
            'subtotal': 1329.98,
            'discount': 0.00,
            'shipping': 0.00,
            'payment_method': 'credit_card',
            'payment_verified': True,
            'created_at': datetime(2024, 11, 1, 10, 30)
        },
        {
            'user_id': 1,
            'order_number': 'ORD-2024-002',
            'status': 'processing',
            'total': 89.99,
            'subtotal': 89.99,
            'discount': 0.00,
            'shipping': 0.00,
            'payment_method': 'paypal',
            'payment_verified': True,
            'created_at': datetime(2024, 11, 28, 15, 20)
        },
        {
            'user_id': 2,
            'order_number': 'ORD-2024-003',
            'status': 'delivered',
            'total': 449.99,
            'subtotal': 449.99,
            'discount': 0.00,
            'shipping': 0.00,
            'payment_method': 'credit_card',
            'payment_verified': True,
            'created_at': datetime(2024, 11, 10, 9, 45)
        }
    ]
    
    orders = []
    for order_data in orders_data:
        order = Order(**order_data)
        orders.append(order)
        session.add(order)
    
    session.commit()
    print(f"✅ Created {len(orders)} orders")
    
    # ========== Order Items ==========
    order_items_data = [
        {'order_id': 1, 'product_id': 1, 'quantity': 1, 'price': 1299.99},
        {'order_id': 1, 'product_id': 2, 'quantity': 1, 'price': 29.99},
        {'order_id': 2, 'product_id': 3, 'quantity': 1, 'price': 89.99},
        {'order_id': 3, 'product_id': 4, 'quantity': 1, 'price': 449.99}
    ]
    
    order_items = []
    for item_data in order_items_data:
        item = OrderItem(**item_data)
        order_items.append(item)
        session.add(item)
    
    session.commit()
    print(f"✅ Created {len(order_items)} order items")
    
    # ========== Cart Items (for Alice) ==========
    cart_items_data = [
        {'user_id': 1, 'product_id': 6, 'quantity': 1, 'price': 159.99},
        {'user_id': 1, 'product_id': 7, 'quantity': 2, 'price': 129.99}
    ]
    
    cart_items = []
    for item_data in cart_items_data:
        item = CartItem(**item_data)
        cart_items.append(item)
        session.add(item)
    
    session.commit()
    print(f"✅ Created {len(cart_items)} cart items")
    
    print("\n✅ Database seeding complete!")
    print(f"\n📊 Summary:")
    print(f"   - {len(users)} users")
    print(f"   - {len(products)} products")
    print(f"   - {len(reviews)} reviews")
    print(f"   - {len(coupons)} coupons")
    print(f"   - {len(orders)} orders")
    print(f"   - {len(order_items)} order items")
    print(f"   - {len(cart_items)} cart items")
    
    return session


if __name__ == '__main__':
    seed_database()
