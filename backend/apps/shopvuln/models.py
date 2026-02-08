"""
ShopVuln Database Models
Educational e-commerce application for AegisForge
Demonstrates realistic e-commerce database design
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class ShopUser(Base):
    """User account model for shopping platform"""
    __tablename__ = 'shop_users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    phone = Column(String(20))
    address = Column(Text)
    role = Column(String(20), default='user')
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    orders = relationship('Order', back_populates='user', cascade='all, delete-orphan')
    reviews = relationship('Review', back_populates='user', cascade='all, delete-orphan')
    cart = relationship('CartItem', back_populates='user', cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convert user to dictionary (exclude password)"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'phone': self.phone,
            'address': self.address,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Product(Base):
    """Product model"""
    __tablename__ = 'products'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)
    price = Column(Float, nullable=False)
    description = Column(Text)
    stock = Column(Integer, default=0)
    image = Column(String(200))
    rating = Column(Float, default=0.0)
    reviews_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    reviews = relationship('Review', back_populates='product', cascade='all, delete-orphan')
    order_items = relationship('OrderItem', back_populates='product')
    cart_items = relationship('CartItem', back_populates='product')
    
    def to_dict(self):
        """Convert product to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'price': self.price,
            'description': self.description,
            'stock': self.stock,
            'image': self.image,
            'rating': self.rating,
            'reviews_count': self.reviews_count,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Review(Base):
    """Product review model"""
    __tablename__ = 'reviews'
    
    id = Column(Integer, primary_key=True)
    product_id = Column(Integer, ForeignKey('products.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('shop_users.id'), nullable=False)
    username = Column(String(50), nullable=False)
    rating = Column(Integer, nullable=False)
    title = Column(String(200))
    comment = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    product = relationship('Product', back_populates='reviews')
    user = relationship('ShopUser', back_populates='reviews')
    
    def to_dict(self):
        """Convert review to dictionary"""
        return {
            'id': self.id,
            'product_id': self.product_id,
            'user_id': self.user_id,
            'username': self.username,
            'rating': self.rating,
            'title': self.title,
            'comment': self.comment,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Order(Base):
    """Order model"""
    __tablename__ = 'orders'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('shop_users.id'), nullable=False)
    order_number = Column(String(50), unique=True, nullable=False, index=True)
    status = Column(String(20), default='processing')
    total = Column(Float, nullable=False)
    subtotal = Column(Float, nullable=False)
    discount = Column(Float, default=0.0)
    shipping = Column(Float, default=0.0)
    payment_method = Column(String(50))
    payment_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship('ShopUser', back_populates='orders')
    items = relationship('OrderItem', back_populates='order', cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convert order to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'order_number': self.order_number,
            'status': self.status,
            'total': self.total,
            'subtotal': self.subtotal,
            'discount': self.discount,
            'shipping': self.shipping,
            'payment_method': self.payment_method,
            'payment_verified': self.payment_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'items': [item.to_dict() for item in self.items] if hasattr(self, 'items') else []
        }


class OrderItem(Base):
    """Order item model"""
    __tablename__ = 'order_items'
    
    id = Column(Integer, primary_key=True)
    order_id = Column(Integer, ForeignKey('orders.id'), nullable=False)
    product_id = Column(Integer, ForeignKey('products.id'), nullable=False)
    quantity = Column(Integer, nullable=False)
    price = Column(Float, nullable=False)
    
    # Relationships
    order = relationship('Order', back_populates='items')
    product = relationship('Product', back_populates='order_items')
    
    def to_dict(self):
        """Convert order item to dictionary"""
        return {
            'id': self.id,
            'order_id': self.order_id,
            'product_id': self.product_id,
            'quantity': self.quantity,
            'price': self.price,
            'product': self.product.to_dict() if self.product else None
        }


class CartItem(Base):
    """Shopping cart item model"""
    __tablename__ = 'cart_items'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('shop_users.id'), nullable=False)
    product_id = Column(Integer, ForeignKey('products.id'), nullable=False)
    quantity = Column(Integer, nullable=False, default=1)
    price = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship('ShopUser', back_populates='cart')
    product = relationship('Product', back_populates='cart_items')
    
    def to_dict(self):
        """Convert cart item to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'product_id': self.product_id,
            'quantity': self.quantity,
            'price': self.price,
            'product': self.product.to_dict() if self.product else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Coupon(Base):
    """Discount coupon model"""
    __tablename__ = 'coupons'
    
    id = Column(Integer, primary_key=True)
    code = Column(String(50), unique=True, nullable=False, index=True)
    discount_type = Column(String(20), nullable=False)  # 'percentage' or 'fixed'
    discount_value = Column(Float, nullable=False)
    min_purchase = Column(Float, default=0.0)
    max_uses = Column(Integer, default=1000)
    max_uses_per_user = Column(Integer, default=1)
    valid_from = Column(DateTime, nullable=False)
    valid_until = Column(DateTime, nullable=False)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    usages = relationship('CouponUsage', back_populates='coupon', cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convert coupon to dictionary"""
        return {
            'id': self.id,
            'code': self.code,
            'discount_type': self.discount_type,
            'discount_value': self.discount_value,
            'min_purchase': self.min_purchase,
            'max_uses': self.max_uses,
            'max_uses_per_user': self.max_uses_per_user,
            'valid_from': self.valid_from.isoformat() if self.valid_from else None,
            'valid_until': self.valid_until.isoformat() if self.valid_until else None,
            'active': self.active
        }


class CouponUsage(Base):
    """Track coupon usage per user"""
    __tablename__ = 'coupon_usages'
    
    id = Column(Integer, primary_key=True)
    coupon_id = Column(Integer, ForeignKey('coupons.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('shop_users.id'), nullable=False)
    order_id = Column(Integer, ForeignKey('orders.id'))
    used_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    coupon = relationship('Coupon', back_populates='usages')
    
    def to_dict(self):
        """Convert coupon usage to dictionary"""
        return {
            'id': self.id,
            'coupon_id': self.coupon_id,
            'user_id': self.user_id,
            'order_id': self.order_id,
            'used_at': self.used_at.isoformat() if self.used_at else None
        }
