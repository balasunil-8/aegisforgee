#!/usr/bin/env python3
"""
AegisForge Universal Setup Script
Cross-platform installation and configuration
Version 2.0
"""

import sys
import os
import subprocess
import platform
from pathlib import Path


def print_banner():
    """Print installation banner"""
    print("\n" + "="*60)
    print("  AegisForge Universal Setup Script v2.0")
    print("="*60 + "\n")


def check_python_version():
    """Verify Python version"""
    print("[1/6] Checking Python version...")
    version = sys.version_info
    
    if version < (3, 8):
        print(f"❌ ERROR: Python 3.8 or higher required")
        print(f"   Current version: {version.major}.{version.minor}.{version.micro}")
        print(f"   Please upgrade Python from https://www.python.org/downloads/")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} detected")
    return True


def create_virtual_environment():
    """Create Python virtual environment"""
    print("\n[2/6] Setting up virtual environment...")
    
    venv_path = Path('.venv')
    
    if venv_path.exists():
        print("ℹ️  Virtual environment already exists")
        return True
    
    try:
        print("   Creating virtual environment...")
        subprocess.run([sys.executable, '-m', 'venv', '.venv'], check=True)
        print("✅ Virtual environment created")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create virtual environment: {e}")
        return False


def get_pip_command():
    """Get the appropriate pip command for the platform"""
    if platform.system() == 'Windows':
        return ['.venv\\Scripts\\pip.exe']
    else:
        return ['.venv/bin/pip']


def get_python_command():
    """Get the appropriate python command for the platform"""
    if platform.system() == 'Windows':
        return ['.venv\\Scripts\\python.exe']
    else:
        return ['.venv/bin/python']


def install_dependencies():
    """Install Python dependencies"""
    print("\n[3/6] Installing dependencies...")
    
    requirements_file = Path('requirements.txt')
    
    if not requirements_file.exists():
        print("❌ requirements.txt not found")
        return False
    
    try:
        pip_cmd = get_pip_command()
        
        # Upgrade pip first
        print("   Upgrading pip...")
        subprocess.run(
            pip_cmd + ['install', '--upgrade', 'pip'],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Install dependencies
        print("   Installing packages from requirements.txt...")
        print("   This may take 2-5 minutes...")
        
        result = subprocess.run(
            pip_cmd + ['install', '-r', 'requirements.txt'],
            check=True,
            capture_output=True,
            text=True
        )
        
        print("✅ All dependencies installed")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies")
        print(f"   Error: {e}")
        print("\n   Try running manually:")
        print(f"   {' '.join(pip_cmd)} install -r requirements.txt")
        return False


def initialize_databases():
    """Initialize application databases"""
    print("\n[4/6] Initializing databases...")
    
    python_cmd = get_python_command()
    
    databases = [
        ('backend/apps/securebank/database.py', 'SecureBank'),
        ('backend/apps/shopvuln/database.py', 'ShopVuln'),
    ]
    
    success_count = 0
    
    for db_script, name in databases:
        db_path = Path(db_script)
        
        if not db_path.exists():
            print(f"⚠️  Warning: {name} database script not found")
            continue
        
        try:
            print(f"   Initializing {name} database...")
            subprocess.run(
                python_cmd + [str(db_path)],
                check=True,
                capture_output=True
            )
            print(f"✅ {name} database initialized")
            success_count += 1
        except subprocess.CalledProcessError as e:
            print(f"⚠️  Warning: Failed to initialize {name} database")
    
    return success_count > 0


def seed_databases():
    """Seed databases with test data"""
    print("\n[5/6] Seeding databases with test data...")
    
    python_cmd = get_python_command()
    
    seed_scripts = [
        ('backend/apps/securebank/seed_data.py', 'SecureBank'),
        ('backend/apps/shopvuln/seed_data.py', 'ShopVuln'),
    ]
    
    for seed_script, name in seed_scripts:
        seed_path = Path(seed_script)
        
        if not seed_path.exists():
            continue
        
        try:
            subprocess.run(
                python_cmd + [str(seed_path)],
                check=True,
                capture_output=True
            )
            print(f"✅ {name} test data seeded")
        except subprocess.CalledProcessError:
            print(f"⚠️  Warning: Failed to seed {name} data")


def run_health_check():
    """Run system health check"""
    print("\n[6/6] Running health check...")
    
    python_cmd = get_python_command()
    health_check_script = Path('scripts/python/health_check.py')
    
    if not health_check_script.exists():
        print("⚠️  Health check script not found - skipping")
        return True
    
    try:
        result = subprocess.run(
            python_cmd + [str(health_check_script)],
            check=False
        )
        return result.returncode == 0
    except Exception as e:
        print(f"⚠️  Health check failed: {e}")
        return False


def print_success_message():
    """Print success message with next steps"""
    print("\n" + "="*60)
    print("  ✅ Installation Complete!")
    print("="*60 + "\n")
    
    print("AegisForge has been successfully installed!\n")
    
    print("📚 Next Steps:\n")
    
    if platform.system() == 'Windows':
        print("1. Start all applications:")
        print("   scripts\\windows\\start_all_apps.bat\n")
        print("2. Or use the Python launcher:")
        print("   .venv\\Scripts\\python.exe scripts\\python\\launcher.py\n")
    else:
        print("1. Activate virtual environment:")
        print("   source .venv/bin/activate\n")
        print("2. Start all applications:")
        print("   ./scripts/linux/start_all_apps.sh\n")
        print("3. Or use the Python launcher:")
        print("   python scripts/python/launcher.py\n")
    
    print("3. Read the quick start guide:")
    print("   QUICKSTART.md\n")
    
    print("4. Access applications at:")
    print("   - SecureBank Red:  http://localhost:5000")
    print("   - SecureBank Blue: http://localhost:5001")
    print("   - ShopVuln Red:    http://localhost:5002")
    print("   - ShopVuln Blue:   http://localhost:5003\n")
    
    print("🔑 Test Credentials:")
    print("   Username: admin")
    print("   Password: admin123\n")
    
    print("="*60 + "\n")


def print_failure_message():
    """Print failure message with troubleshooting tips"""
    print("\n" + "="*60)
    print("  ⚠️  Installation Incomplete")
    print("="*60 + "\n")
    
    print("Some steps failed during installation.\n")
    
    print("🔧 Troubleshooting:\n")
    print("1. Check Python version:")
    print("   python --version  # Should be 3.8 or higher\n")
    print("2. Manually install dependencies:")
    print("   pip install -r requirements.txt\n")
    print("3. Check the detailed error messages above\n")
    print("4. See INSTALL.md for detailed installation instructions\n")
    print("5. Get help:")
    print("   - Check docs/troubleshooting/")
    print("   - Open an issue on GitHub\n")
    
    print("="*60 + "\n")


def main():
    """Main setup routine"""
    print_banner()
    
    # Change to script's directory
    script_dir = Path(__file__).parent.parent.parent
    if script_dir.exists():
        os.chdir(script_dir)
    
    # Run setup steps
    success = True
    
    if not check_python_version():
        success = False
    else:
        if not create_virtual_environment():
            success = False
        elif not install_dependencies():
            success = False
        elif not initialize_databases():
            success = False
        else:
            seed_databases()  # Optional - don't fail on this
            health_passed = run_health_check()
            if not health_passed:
                print("\n⚠️  Note: Some health checks failed, but you can still proceed")
    
    # Print final message
    if success:
        print_success_message()
        sys.exit(0)
    else:
        print_failure_message()
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
