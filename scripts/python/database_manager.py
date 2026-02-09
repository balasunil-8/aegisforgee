#!/usr/bin/env python3
"""
AegisForge Database Manager
Database initialization, backup, restore, and management tools
Version 2.0
"""

import sys
import os
import shutil
import sqlite3
from pathlib import Path
from datetime import datetime
import argparse


class DatabaseManager:
    """Manage AegisForge databases"""
    
    DATABASES = {
        'securebank': {
            'path': 'backend/apps/securebank/securebank.db',
            'init_script': 'backend/apps/securebank/database.py',
            'seed_script': 'backend/apps/securebank/seed_data.py',
        },
        'shopvuln': {
            'path': 'backend/apps/shopvuln/shopvuln.db',
            'init_script': 'backend/apps/shopvuln/database.py',
            'seed_script': 'backend/apps/shopvuln/seed_data.py',
        },
    }
    
    def __init__(self):
        self.backup_dir = Path('backups')
        self.backup_dir.mkdir(exist_ok=True)
    
    def list_databases(self):
        """List all databases and their status"""
        print("\n" + "="*60)
        print("AegisForge Databases")
        print("="*60 + "\n")
        
        for name, info in self.DATABASES.items():
            db_path = Path(info['path'])
            
            print(f"📁 {name.upper()}")
            print(f"   Path: {db_path}")
            
            if db_path.exists():
                size = db_path.stat().st_size / 1024  # KB
                modified = datetime.fromtimestamp(db_path.stat().st_mtime)
                print(f"   Status: ✅ EXISTS")
                print(f"   Size: {size:.2f} KB")
                print(f"   Modified: {modified.strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Get table count
                try:
                    conn = sqlite3.connect(str(db_path))
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
                    )
                    table_count = cursor.fetchone()[0]
                    conn.close()
                    print(f"   Tables: {table_count}")
                except Exception as e:
                    print(f"   Tables: ERROR - {e}")
            else:
                print(f"   Status: ❌ NOT FOUND")
            
            print()
    
    def initialize_database(self, db_name):
        """Initialize a specific database"""
        if db_name not in self.DATABASES:
            print(f"❌ Unknown database: {db_name}")
            print(f"   Available: {', '.join(self.DATABASES.keys())}")
            return False
        
        info = self.DATABASES[db_name]
        init_script = Path(info['init_script'])
        
        if not init_script.exists():
            print(f"❌ Initialization script not found: {init_script}")
            return False
        
        print(f"\n🔨 Initializing {db_name} database...")
        
        try:
            import subprocess
            result = subprocess.run(
                [sys.executable, str(init_script)],
                check=True,
                capture_output=True,
                text=True
            )
            print(f"✅ {db_name} database initialized successfully")
            
            if result.stdout:
                print(result.stdout)
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to initialize {db_name} database")
            if e.stderr:
                print(e.stderr)
            return False
    
    def seed_database(self, db_name):
        """Seed a database with test data"""
        if db_name not in self.DATABASES:
            print(f"❌ Unknown database: {db_name}")
            return False
        
        info = self.DATABASES[db_name]
        seed_script = Path(info['seed_script'])
        
        if not seed_script.exists():
            print(f"⚠️  Seed script not found: {seed_script}")
            return False
        
        print(f"\n🌱 Seeding {db_name} database...")
        
        try:
            import subprocess
            result = subprocess.run(
                [sys.executable, str(seed_script)],
                check=True,
                capture_output=True,
                text=True
            )
            print(f"✅ {db_name} database seeded successfully")
            
            if result.stdout:
                print(result.stdout)
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to seed {db_name} database")
            if e.stderr:
                print(e.stderr)
            return False
    
    def backup_database(self, db_name):
        """Create backup of a database"""
        if db_name not in self.DATABASES:
            print(f"❌ Unknown database: {db_name}")
            return False
        
        info = self.DATABASES[db_name]
        db_path = Path(info['path'])
        
        if not db_path.exists():
            print(f"❌ Database not found: {db_path}")
            return False
        
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"{db_name}_{timestamp}.db"
        backup_path = self.backup_dir / backup_name
        
        print(f"\n💾 Backing up {db_name} database...")
        print(f"   Source: {db_path}")
        print(f"   Backup: {backup_path}")
        
        try:
            shutil.copy2(db_path, backup_path)
            size = backup_path.stat().st_size / 1024  # KB
            print(f"✅ Backup created successfully ({size:.2f} KB)")
            return True
        except Exception as e:
            print(f"❌ Backup failed: {e}")
            return False
    
    def restore_database(self, db_name, backup_file):
        """Restore database from backup"""
        if db_name not in self.DATABASES:
            print(f"❌ Unknown database: {db_name}")
            return False
        
        backup_path = Path(backup_file)
        
        if not backup_path.exists():
            print(f"❌ Backup file not found: {backup_path}")
            return False
        
        info = self.DATABASES[db_name]
        db_path = Path(info['path'])
        
        print(f"\n♻️  Restoring {db_name} database...")
        print(f"   Source: {backup_path}")
        print(f"   Target: {db_path}")
        
        # Create backup of current database if it exists
        if db_path.exists():
            current_backup = self.backup_dir / f"{db_name}_before_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            shutil.copy2(db_path, current_backup)
            print(f"   Created safety backup: {current_backup}")
        
        try:
            shutil.copy2(backup_path, db_path)
            print(f"✅ Database restored successfully")
            return True
        except Exception as e:
            print(f"❌ Restore failed: {e}")
            return False
    
    def delete_database(self, db_name):
        """Delete a database (with confirmation)"""
        if db_name not in self.DATABASES:
            print(f"❌ Unknown database: {db_name}")
            return False
        
        info = self.DATABASES[db_name]
        db_path = Path(info['path'])
        
        if not db_path.exists():
            print(f"⚠️  Database already deleted: {db_path}")
            return True
        
        print(f"\n⚠️  WARNING: This will permanently delete {db_name} database!")
        print(f"   Path: {db_path}")
        
        confirm = input("\n   Type 'DELETE' to confirm: ")
        
        if confirm != 'DELETE':
            print("❌ Deletion cancelled")
            return False
        
        # Create backup before deletion
        self.backup_database(db_name)
        
        try:
            db_path.unlink()
            print(f"✅ Database deleted successfully")
            return True
        except Exception as e:
            print(f"❌ Deletion failed: {e}")
            return False
    
    def list_backups(self):
        """List all database backups"""
        print("\n" + "="*60)
        print("Database Backups")
        print("="*60 + "\n")
        
        backups = sorted(self.backup_dir.glob('*.db'), key=lambda x: x.stat().st_mtime, reverse=True)
        
        if not backups:
            print("No backups found\n")
            return
        
        for backup in backups:
            size = backup.stat().st_size / 1024  # KB
            modified = datetime.fromtimestamp(backup.stat().st_mtime)
            print(f"📦 {backup.name}")
            print(f"   Size: {size:.2f} KB")
            print(f"   Created: {modified.strftime('%Y-%m-%d %H:%M:%S')}")
            print()
    
    def reset_all(self):
        """Reset all databases (reinitialize and seed)"""
        print("\n" + "="*60)
        print("Resetting All Databases")
        print("="*60 + "\n")
        
        print("⚠️  This will DELETE and RECREATE all databases!")
        confirm = input("Type 'RESET' to confirm: ")
        
        if confirm != 'RESET':
            print("❌ Reset cancelled")
            return False
        
        # Backup all databases first
        print("\n1. Creating backups...")
        for db_name in self.DATABASES.keys():
            if Path(self.DATABASES[db_name]['path']).exists():
                self.backup_database(db_name)
        
        # Initialize and seed each database
        print("\n2. Reinitializing databases...")
        success_count = 0
        
        for db_name in self.DATABASES.keys():
            if self.initialize_database(db_name):
                if self.seed_database(db_name):
                    success_count += 1
        
        print(f"\n✅ Reset complete: {success_count}/{len(self.DATABASES)} databases")
        return success_count == len(self.DATABASES)


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description='AegisForge Database Manager',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python database_manager.py list
  python database_manager.py init securebank
  python database_manager.py backup shopvuln
  python database_manager.py restore securebank backups/securebank_20240101_120000.db
  python database_manager.py reset
        '''
    )
    
    parser.add_argument(
        'action',
        choices=['list', 'init', 'seed', 'backup', 'restore', 'delete', 'backups', 'reset'],
        help='Action to perform'
    )
    
    parser.add_argument(
        'database',
        nargs='?',
        choices=['securebank', 'shopvuln'],
        help='Database name (required for most actions)'
    )
    
    parser.add_argument(
        'backup_file',
        nargs='?',
        help='Backup file path (required for restore action)'
    )
    
    args = parser.parse_args()
    
    manager = DatabaseManager()
    
    # Execute action
    if args.action == 'list':
        manager.list_databases()
    
    elif args.action == 'backups':
        manager.list_backups()
    
    elif args.action == 'reset':
        manager.reset_all()
    
    elif args.action in ['init', 'seed', 'backup', 'delete']:
        if not args.database:
            print(f"❌ Database name required for '{args.action}' action")
            parser.print_help()
            sys.exit(1)
        
        if args.action == 'init':
            success = manager.initialize_database(args.database)
        elif args.action == 'seed':
            success = manager.seed_database(args.database)
        elif args.action == 'backup':
            success = manager.backup_database(args.database)
        elif args.action == 'delete':
            success = manager.delete_database(args.database)
        
        sys.exit(0 if success else 1)
    
    elif args.action == 'restore':
        if not args.database or not args.backup_file:
            print(f"❌ Database name and backup file required for restore")
            parser.print_help()
            sys.exit(1)
        
        success = manager.restore_database(args.database, args.backup_file)
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
