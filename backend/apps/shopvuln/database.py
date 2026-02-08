"""
ShopVuln Database Initialization
Creates database and tables for the e-commerce application
"""

import sqlite3
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), 'shopvuln.db')


def get_connection():
    """Get SQLite database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Initialize database and create all tables"""
    # Remove existing database
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"🗑️  Removed existing database: {DB_PATH}")
    
    # Create new database with SQLAlchemy
    engine = create_engine(f'sqlite:///{DB_PATH}')
    Base.metadata.create_all(engine)
    
    print(f"✅ Database initialized: {DB_PATH}")
    print("📊 Created tables:")
    for table in Base.metadata.tables.keys():
        print(f"   - {table}")
    
    return engine


def get_session():
    """Get SQLAlchemy session"""
    engine = create_engine(f'sqlite:///{DB_PATH}')
    Session = sessionmaker(bind=engine)
    return Session()


if __name__ == '__main__':
    init_database()
    print("\n✅ Database initialization complete!")
