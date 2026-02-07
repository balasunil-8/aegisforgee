"""
SecureBank Database Setup
Initializes SQLite database and creates tables
"""

import sqlite3
import os
from datetime import datetime

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), 'securebank.db')


def init_database():
    """Initialize database with tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create bank_users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS bank_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        phone TEXT,
        address TEXT,
        role TEXT DEFAULT 'user',
        is_active INTEGER DEFAULT 1,
        created_at TEXT,
        last_login TEXT
    )
    ''')
    
    # Create bank_accounts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS bank_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        account_number TEXT UNIQUE NOT NULL,
        account_type TEXT NOT NULL,
        balance REAL DEFAULT 0.0,
        currency TEXT DEFAULT 'USD',
        status TEXT DEFAULT 'active',
        opened_date TEXT,
        FOREIGN KEY (user_id) REFERENCES bank_users(id)
    )
    ''')
    
    # Create transactions table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_account_id INTEGER,
        to_account_id INTEGER,
        from_account_number TEXT NOT NULL,
        to_account_number TEXT NOT NULL,
        amount REAL NOT NULL,
        type TEXT NOT NULL,
        status TEXT DEFAULT 'completed',
        note TEXT,
        reference TEXT UNIQUE,
        timestamp TEXT,
        FOREIGN KEY (from_account_id) REFERENCES bank_accounts(id),
        FOREIGN KEY (to_account_id) REFERENCES bank_accounts(id)
    )
    ''')
    
    # Create beneficiaries table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS beneficiaries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        account_number TEXT NOT NULL,
        bank_name TEXT DEFAULT 'AegisBank',
        nickname TEXT,
        added_date TEXT,
        FOREIGN KEY (user_id) REFERENCES bank_users(id)
    )
    ''')
    
    # Create user_settings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        email_notifications INTEGER DEFAULT 1,
        sms_notifications INTEGER DEFAULT 0,
        transaction_alerts INTEGER DEFAULT 1,
        login_alerts INTEGER DEFAULT 1,
        theme TEXT DEFAULT 'light',
        language TEXT DEFAULT 'en',
        FOREIGN KEY (user_id) REFERENCES bank_users(id)
    )
    ''')
    
    # Create indexes for better performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON bank_users(username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_accounts_user ON bank_accounts(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_accounts_number ON bank_accounts(account_number)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_transactions_from ON transactions(from_account_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_transactions_to ON transactions(to_account_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_transactions_timestamp ON transactions(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_beneficiaries_user ON beneficiaries(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_settings_user ON user_settings(user_id)')
    
    conn.commit()
    conn.close()
    
    print(f"✅ Database initialized at {DB_PATH}")


def get_connection():
    """Get database connection with row factory"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


if __name__ == '__main__':
    init_database()
