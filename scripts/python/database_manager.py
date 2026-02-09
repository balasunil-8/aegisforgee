#!/usr/bin/env python3
"""AegisForge Database Manager"""
import sys
import os
import sqlite3
from pathlib import Path


class DatabaseManager:
    """Manage AegisForge databases"""
    
    def __init__(self):
        self.databases = {
            'securebank': 'backend/apps/securebank/securebank.db',
            'shopvuln': 'backend/apps/shopvuln/shopvuln.db'
        }
    
    def list_databases(self):
        """List all databases and their status"""
        print("\n" + "="*50)
        print("  AegisForge Databases")
        print("="*50 + "\n")
        
        for name, path in self.databases.items():
            if Path(path).exists():
                size = Path(path).stat().st_size / 1024  # KB
                conn = sqlite3.connect(path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                conn.close()
                
                print(f"✓ {name.upper()}")
                print(f"  Path: {path}")
                print(f"  Size: {size:.1f} KB")
                print(f"  Tables: {len(tables)}")
                print()
            else:
                print(f"✗ {name.upper()}")
                print(f"  Path: {path}")
                print(f"  Status: NOT FOUND")
                print()
    
    def backup_database(self, db_name):
        """Backup a database"""
        if db_name not in self.databases:
            print(f"Error: Unknown database '{db_name}'")
            return False
        
        db_path = self.databases[db_name]
        if not Path(db_path).exists():
            print(f"Error: Database not found at {db_path}")
            return False
        
        backup_path = f"{db_path}.backup"
        try:
            import shutil
            shutil.copy2(db_path, backup_path)
            print(f"✓ Backed up {db_name} to {backup_path}")
            return True
        except Exception as e:
            print(f"✗ Backup failed: {e}")
            return False
    
    def restore_database(self, db_name):
        """Restore a database from backup"""
        if db_name not in self.databases:
            print(f"Error: Unknown database '{db_name}'")
            return False
        
        db_path = self.databases[db_name]
        backup_path = f"{db_path}.backup"
        
        if not Path(backup_path).exists():
            print(f"Error: Backup not found at {backup_path}")
            return False
        
        try:
            import shutil
            shutil.copy2(backup_path, db_path)
            print(f"✓ Restored {db_name} from backup")
            return True
        except Exception as e:
            print(f"✗ Restore failed: {e}")
            return False
    
    def reset_database(self, db_name):
        """Reset a database (delete and reinitialize)"""
        if db_name not in self.databases:
            print(f"Error: Unknown database '{db_name}'")
            return False
        
        db_path = self.databases[db_name]
        
        # Delete existing database
        if Path(db_path).exists():
            os.remove(db_path)
            print(f"✓ Deleted {db_name}")
        
        # Reinitialize
        app_dir = os.path.dirname(db_path)
        os.chdir(app_dir)
        
        # Run database.py and seed_data.py
        import subprocess
        
        try:
            subprocess.run([sys.executable, "database.py"], check=True)
            print(f"✓ Reinitialized {db_name} schema")
            
            subprocess.run([sys.executable, "seed_data.py"], check=True)
            print(f"✓ Seeded {db_name} data")
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Reset failed: {e}")
            return False
        finally:
            os.chdir("../../..")


def main():
    """Main entry point"""
    manager = DatabaseManager()
    
    if len(sys.argv) < 2:
        print("AegisForge Database Manager")
        print("\nUsage:")
        print("  python database_manager.py list")
        print("  python database_manager.py backup <db_name>")
        print("  python database_manager.py restore <db_name>")
        print("  python database_manager.py reset <db_name>")
        print("\nDatabases: securebank, shopvuln")
        return 1
    
    command = sys.argv[1]
    
    if command == "list":
        manager.list_databases()
    elif command == "backup":
        if len(sys.argv) < 3:
            print("Error: Specify database name (securebank or shopvuln)")
            return 1
        manager.backup_database(sys.argv[2])
    elif command == "restore":
        if len(sys.argv) < 3:
            print("Error: Specify database name (securebank or shopvuln)")
            return 1
        manager.restore_database(sys.argv[2])
    elif command == "reset":
        if len(sys.argv) < 3:
            print("Error: Specify database name (securebank or shopvuln)")
            return 1
        
        # Confirmation
        db_name = sys.argv[2]
        response = input(f"Are you sure you want to reset {db_name}? (yes/no): ")
        if response.lower() == 'yes':
            manager.reset_database(db_name)
        else:
            print("Cancelled")
    else:
        print(f"Error: Unknown command '{command}'")
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
