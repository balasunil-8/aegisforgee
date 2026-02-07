"""
SecureBank Database Models
Educational banking application for AegisForge
Demonstrates secure database design with SQLAlchemy
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class BankUser(Base):
    """User account model for banking application"""
    __tablename__ = 'bank_users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)  # Should be hashed with bcrypt
    email = Column(String(100), unique=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    phone = Column(String(20))
    address = Column(Text)
    role = Column(String(20), default='user')  # 'user' or 'admin'
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    accounts = relationship('BankAccount', back_populates='user', cascade='all, delete-orphan')
    beneficiaries = relationship('Beneficiary', back_populates='user', cascade='all, delete-orphan')
    settings = relationship('UserSettings', back_populates='user', uselist=False, cascade='all, delete-orphan')
    
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


class BankAccount(Base):
    """Bank account model"""
    __tablename__ = 'bank_accounts'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('bank_users.id'), nullable=False, index=True)
    account_number = Column(String(20), unique=True, nullable=False, index=True)
    account_type = Column(String(20), nullable=False)  # 'Checking', 'Savings', 'Credit'
    balance = Column(Float, default=0.0, nullable=False)
    currency = Column(String(3), default='USD')
    status = Column(String(20), default='active')  # 'active', 'frozen', 'closed'
    opened_date = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship('BankUser', back_populates='accounts')
    transactions_from = relationship('Transaction', foreign_keys='Transaction.from_account_id', back_populates='from_account')
    transactions_to = relationship('Transaction', foreign_keys='Transaction.to_account_id', back_populates='to_account')
    
    def to_dict(self):
        """Convert account to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'account_number': self.account_number,
            'account_type': self.account_type,
            'balance': self.balance,
            'currency': self.currency,
            'status': self.status,
            'opened_date': self.opened_date.isoformat() if self.opened_date else None
        }


class Transaction(Base):
    """Transaction model for money transfers"""
    __tablename__ = 'transactions'
    
    id = Column(Integer, primary_key=True)
    from_account_id = Column(Integer, ForeignKey('bank_accounts.id'), index=True)
    to_account_id = Column(Integer, ForeignKey('bank_accounts.id'), index=True)
    from_account_number = Column(String(20), nullable=False)
    to_account_number = Column(String(20), nullable=False)
    amount = Column(Float, nullable=False)
    type = Column(String(20), nullable=False)  # 'transfer', 'internal_transfer', 'deposit', 'withdrawal'
    status = Column(String(20), default='completed')  # 'pending', 'completed', 'failed', 'cancelled'
    note = Column(Text)
    reference = Column(String(50), unique=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    from_account = relationship('BankAccount', foreign_keys=[from_account_id], back_populates='transactions_from')
    to_account = relationship('BankAccount', foreign_keys=[to_account_id], back_populates='transactions_to')
    
    def to_dict(self):
        """Convert transaction to dictionary"""
        return {
            'id': self.id,
            'from_account': self.from_account_number,
            'to_account': self.to_account_number,
            'amount': self.amount,
            'type': self.type,
            'status': self.status,
            'note': self.note,
            'reference': self.reference,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


class Beneficiary(Base):
    """Saved beneficiary model for quick transfers"""
    __tablename__ = 'beneficiaries'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('bank_users.id'), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    account_number = Column(String(20), nullable=False)
    bank_name = Column(String(100), default='AegisBank')
    nickname = Column(String(50))
    added_date = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship('BankUser', back_populates='beneficiaries')
    
    def to_dict(self):
        """Convert beneficiary to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'account_number': self.account_number,
            'bank_name': self.bank_name,
            'nickname': self.nickname,
            'added_date': self.added_date.isoformat() if self.added_date else None
        }


class UserSettings(Base):
    """User settings and preferences"""
    __tablename__ = 'user_settings'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('bank_users.id'), nullable=False, unique=True, index=True)
    email_notifications = Column(Boolean, default=True)
    sms_notifications = Column(Boolean, default=False)
    transaction_alerts = Column(Boolean, default=True)
    login_alerts = Column(Boolean, default=True)
    theme = Column(String(20), default='light')  # 'light' or 'dark'
    language = Column(String(10), default='en')
    
    # Relationships
    user = relationship('BankUser', back_populates='settings')
    
    def to_dict(self):
        """Convert settings to dictionary"""
        return {
            'email_notifications': self.email_notifications,
            'sms_notifications': self.sms_notifications,
            'transaction_alerts': self.transaction_alerts,
            'login_alerts': self.login_alerts,
            'theme': self.theme,
            'language': self.language
        }
