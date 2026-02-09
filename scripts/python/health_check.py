#!/usr/bin/env python3
"""AegisForge System Health Check"""
import sys
import socket
from pathlib import Path

def check_python():
    """Check Python version"""
    if sys.version_info < (3, 8):
        print("✗ Python 3.8+ required (found {}.{})".format(
            sys.version_info.major, sys.version_info.minor))
        return False
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor}")
    return True

def check_dependencies():
    """Check if required dependencies are installed"""
    required = [
        ('flask', 'Flask'),
        ('flask_cors', 'Flask-CORS'),
        ('sqlalchemy', 'SQLAlchemy'),
        ('flask_sqlalchemy', 'Flask-SQLAlchemy'),
        ('flask_jwt_extended', 'Flask-JWT-Extended')
    ]
    
    missing = []
    for module, name in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(name)
    
    if missing:
        print(f"✗ Missing dependencies: {', '.join(missing)}")
        return False
    
    print("✓ All dependencies installed")
    return True

def check_ports():
    """Check port availability"""
    ports = {
        5000: 'SecureBank Red',
        5001: 'SecureBank Blue',
        5002: 'ShopVuln Red',
        5003: 'ShopVuln Blue'
    }
    
    for port, name in ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', port))
        sock.close()
        status = "In use" if result == 0 else "Available"
        print(f"  Port {port} ({name}): {status}")
    
    return True

def check_databases():
    """Check if database files exist"""
    dbs = [
        ('backend/apps/securebank/securebank.db', 'SecureBank'),
        ('backend/apps/shopvuln/shopvuln.db', 'ShopVuln')
    ]
    
    all_exist = True
    for path, name in dbs:
        if Path(path).exists():
            size = Path(path).stat().st_size / 1024  # KB
            print(f"✓ {name} database found ({size:.1f} KB)")
        else:
            print(f"✗ {name} database missing")
            all_exist = False
    
    return all_exist

def check_disk_space():
    """Check available disk space"""
    try:
        import shutil
        total, used, free = shutil.disk_usage(".")
        free_gb = free // (2**30)  # Convert to GB
        
        if free_gb < 3:
            print(f"⚠ Low disk space: {free_gb}GB (3GB minimum required)")
            return False
        elif free_gb < 5:
            print(f"⚠ Disk space: {free_gb}GB (5GB recommended)")
            return True
        else:
            print(f"✓ Disk space: {free_gb}GB available")
            return True
    except Exception as e:
        print(f"⚠ Could not check disk space: {e}")
        return True

def main():
    """Run all health checks"""
    print("\n" + "="*50)
    print("  AegisForge Health Check")
    print("="*50 + "\n")
    
    results = {
        'Python': check_python(),
        'Dependencies': check_dependencies(),
        'Databases': check_databases(),
        'Disk Space': check_disk_space()
    }
    
    print("\nPort Availability:")
    check_ports()
    
    passed = sum(results.values())
    total = len(results)
    
    print(f"\n{'='*50}")
    print(f"Results: {passed}/{total} checks passed")
    print("="*50)
    
    if passed == total:
        print("\n✓ System ready! All checks passed.")
        print("\nNext steps:")
        print("  1. Start applications: scripts/windows/start_all_apps.bat (Windows)")
        print("                         ./scripts/linux/start_all_apps.sh (Linux/Mac)")
        print("  2. Access: http://localhost:5000")
        print("  3. Login: alice / password123")
        return 0
    else:
        print("\n✗ Issues detected. Please resolve before starting.")
        print("\nSolutions:")
        if not results['Python']:
            print("  - Install Python 3.8 or higher from python.org")
        if not results['Dependencies']:
            print("  - Run: pip install -r requirements.txt")
        if not results['Databases']:
            print("  - Run: scripts/windows/init_databases.bat (Windows)")
            print("         ./scripts/linux/init_databases.sh (Linux/Mac)")
        return 1

if __name__ == '__main__':
    sys.exit(main())
