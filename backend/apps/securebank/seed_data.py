"""
SecureBank Seed Data
Populates database with sample banking data for testing
Includes realistic users, accounts, transactions, and beneficiaries
"""

import sqlite3
from datetime import datetime
from database import DB_PATH, init_database, get_connection


def seed_database():
    """Populate database with sample data"""
    
    # Initialize database first
    init_database()
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # Clear existing data
    cursor.execute('DELETE FROM user_settings')
    cursor.execute('DELETE FROM beneficiaries')
    cursor.execute('DELETE FROM transactions')
    cursor.execute('DELETE FROM bank_accounts')
    cursor.execute('DELETE FROM bank_users')
    
    # Sample users (passwords are plain text for demo - should be hashed in production)
    users = [
        (1, 'alice', 'password123', 'alice@example.com', 'Alice Johnson', '+1-555-0101', 
         '123 Main St, New York, NY 10001', 'user', 1, '2024-01-15 10:00:00', None),
        (2, 'bob', 'securepass456', 'bob@example.com', 'Bob Smith', '+1-555-0102',
         '456 Oak Ave, Los Angeles, CA 90001', 'user', 1, '2024-02-20 14:30:00', None),
        (3, 'admin', 'admin123', 'admin@aegisbank.com', 'System Administrator', '+1-555-0100',
         'AegisBank HQ', 'admin', 1, '2024-01-01 00:00:00', None),
        (4, 'carol', 'carol789', 'carol@example.com', 'Carol White', '+1-555-0103',
         '789 Pine Rd, Chicago, IL 60601', 'user', 1, '2024-03-10 09:15:00', None)
    ]
    
    cursor.executemany('''
    INSERT INTO bank_users (id, username, password, email, full_name, phone, address, role, is_active, created_at, last_login)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', users)
    
    # Sample accounts
    accounts = [
        (1001, 1, '1234567890', 'Checking', 50000.00, 'USD', 'active', '2024-01-15'),
        (1002, 1, '1234567891', 'Savings', 125000.50, 'USD', 'active', '2024-01-15'),
        (1003, 2, '2345678901', 'Checking', 15000.25, 'USD', 'active', '2024-02-20'),
        (1004, 2, '2345678902', 'Savings', 75000.00, 'USD', 'active', '2024-02-20'),
        (1005, 4, '9876543210', 'Checking', 30000.00, 'USD', 'active', '2024-03-10'),
        (1006, 4, '9876543211', 'Savings', 90000.00, 'USD', 'active', '2024-03-10')
    ]
    
    cursor.executemany('''
    INSERT INTO bank_accounts (id, user_id, account_number, account_type, balance, currency, status, opened_date)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', accounts)
    
    # Sample transactions
    transactions = [
        (2001, 1001, 1003, '1234567890', '2345678901', 500.00, 'transfer', 'completed',
         'Rent payment for November', 'TXN20241101001', '2024-11-01 10:30:00'),
        (2002, 1001, 1005, '1234567890', '9876543210', 1250.00, 'transfer', 'completed',
         'Monthly invoice #12345', 'TXN20241115001', '2024-11-15 14:22:00'),
        (2003, 1003, 1001, '2345678901', '1234567890', 200.00, 'transfer', 'completed',
         'Lunch payment', 'TXN20241120001', '2024-11-20 12:45:00'),
        (2004, 1002, 1001, '1234567891', '1234567890', 5000.00, 'internal_transfer', 'completed',
         'Savings to checking transfer', 'TXN20241125001', '2024-11-25 09:15:00'),
        (2005, 1005, 1001, '9876543210', '1234567890', 750.00, 'transfer', 'completed',
         'Payment for services', 'TXN20241201001', '2024-12-01 11:00:00'),
        (2006, 1001, 1003, '1234567890', '2345678901', 300.00, 'transfer', 'completed',
         'Groceries reimbursement', 'TXN20241210001', '2024-12-10 16:30:00'),
        (2007, 1004, 1002, '2345678902', '1234567891', 10000.00, 'transfer', 'completed',
         'Investment transfer', 'TXN20241215001', '2024-12-15 10:00:00'),
        (2008, 1001, None, '1234567890', 'EXTERNAL', 150.00, 'withdrawal', 'completed',
         'ATM withdrawal', 'TXN20241218001', '2024-12-18 14:00:00'),
        (2009, None, 1001, 'EXTERNAL', '1234567890', 3000.00, 'deposit', 'completed',
         'Salary deposit', 'TXN20241220001', '2024-12-20 09:00:00'),
        (2010, 1003, 1005, '2345678901', '9876543210', 425.50, 'transfer', 'completed',
         'Dinner split payment', 'TXN20241222001', '2024-12-22 20:15:00')
    ]
    
    cursor.executemany('''
    INSERT INTO transactions (id, from_account_id, to_account_id, from_account_number, to_account_number, 
                             amount, type, status, note, reference, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', transactions)
    
    # Sample beneficiaries
    beneficiaries = [
        (3001, 1, 'Bob Smith', '2345678901', 'AegisBank', 'Bob', '2024-03-01'),
        (3002, 1, 'Carol White', '9876543210', 'AegisBank', 'Carol', '2024-04-15'),
        (3003, 2, 'Alice Johnson', '1234567890', 'AegisBank', 'Alice', '2024-05-10'),
        (3004, 2, 'Carol White', '9876543210', 'AegisBank', 'Carol W', '2024-06-20'),
        (3005, 4, 'Alice Johnson', '1234567890', 'AegisBank', 'Alice J', '2024-07-05'),
        (3006, 4, 'Bob Smith', '2345678901', 'AegisBank', 'Bob S', '2024-08-12')
    ]
    
    cursor.executemany('''
    INSERT INTO beneficiaries (id, user_id, name, account_number, bank_name, nickname, added_date)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', beneficiaries)
    
    # Sample user settings
    settings = [
        (1, 1, 1, 0, 1, 1, 'light', 'en'),
        (2, 2, 1, 1, 1, 0, 'light', 'en'),
        (3, 3, 1, 1, 1, 1, 'dark', 'en'),
        (4, 4, 0, 0, 1, 1, 'light', 'en')
    ]
    
    cursor.executemany('''
    INSERT INTO user_settings (id, user_id, email_notifications, sms_notifications, transaction_alerts, 
                              login_alerts, theme, language)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', settings)
    
    conn.commit()
    conn.close()
    
    print("✅ Database seeded with sample data")
    print("\n📊 Sample Data Summary:")
    print("   - 4 Users (alice, bob, admin, carol)")
    print("   - 6 Bank Accounts (Checking & Savings)")
    print("   - 10 Transactions (transfers, deposits, withdrawals)")
    print("   - 6 Beneficiaries")
    print("   - 4 User Settings")
    print("\n🔐 Test Credentials:")
    print("   Username: alice    | Password: password123")
    print("   Username: bob      | Password: securepass456")
    print("   Username: admin    | Password: admin123")
    print("   Username: carol    | Password: carol789")


if __name__ == '__main__':
    seed_database()
