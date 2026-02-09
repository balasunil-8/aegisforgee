#!/usr/bin/env python3
"""
AegisForge System Health Check
Comprehensive system verification and diagnostics
Version 2.0
"""

import sys
import os
import platform
import subprocess
import socket
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


class HealthCheck:
    """System health check manager"""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.checks = []
    
    def check(self, name, condition, error_msg="", warning=False):
        """Perform a single check"""
        if condition:
            status = f"{Colors.GREEN}✓ PASS{Colors.END}"
            self.passed += 1
            result = "PASS"
        else:
            if warning:
                status = f"{Colors.YELLOW}⚠ WARN{Colors.END}"
                self.warnings += 1
                result = "WARN"
            else:
                status = f"{Colors.RED}✗ FAIL{Colors.END}"
                self.failed += 1
                result = "FAIL"
        
        print(f"  {status} {name}")
        if not condition and error_msg:
            print(f"       {Colors.YELLOW}→ {error_msg}{Colors.END}")
        
        self.checks.append({
            'name': name,
            'result': result,
            'message': error_msg if not condition else ''
        })
        
        return condition
    
    def print_summary(self):
        """Print summary of all checks"""
        total = self.passed + self.failed + self.warnings
        
        print(f"\n{'='*60}")
        print(f"{Colors.BOLD}Health Check Summary{Colors.END}")
        print(f"{'='*60}\n")
        
        print(f"  Total Checks: {total}")
        print(f"  {Colors.GREEN}Passed: {self.passed}{Colors.END}")
        print(f"  {Colors.RED}Failed: {self.failed}{Colors.END}")
        print(f"  {Colors.YELLOW}Warnings: {self.warnings}{Colors.END}")
        
        print(f"\n{'='*60}\n")
        
        if self.failed == 0 and self.warnings == 0:
            print(f"{Colors.GREEN}{Colors.BOLD}✓ ALL CHECKS PASSED!{Colors.END}")
            print(f"\nAegisForge is ready to use.")
            print(f"\nTo start applications:")
            print(f"  Windows: scripts\\windows\\start_all_apps.bat")
            print(f"  Linux:   ./scripts/linux/start_all_apps.sh")
            return True
        elif self.failed == 0:
            print(f"{Colors.YELLOW}⚠ CHECKS PASSED WITH WARNINGS{Colors.END}")
            print(f"\nAegisForge should work, but some features may be limited.")
            return True
        else:
            print(f"{Colors.RED}✗ SOME CHECKS FAILED{Colors.END}")
            print(f"\nPlease fix the issues above before running AegisForge.")
            return False


def check_python_version(hc):
    """Check Python version"""
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    print(f"\n[1/12] Python Version: {version_str}")
    
    hc.check(
        "Python 3.8 or higher",
        version >= (3, 8),
        "Please upgrade to Python 3.8 or higher"
    )


def check_system_info(hc):
    """Check system information"""
    print(f"\n[2/12] System Information")
    
    os_name = platform.system()
    print(f"  OS: {os_name} {platform.release()}")
    print(f"  Architecture: {platform.machine()}")
    
    hc.check("Operating system detected", True)


def check_dependencies(hc):
    """Check Python dependencies"""
    print(f"\n[3/12] Python Dependencies")
    
    required = [
        ('flask', 'Flask'),
        ('flask_sqlalchemy', 'Flask-SQLAlchemy'),
        ('flask_cors', 'Flask-CORS'),
        ('sqlalchemy', 'SQLAlchemy'),
        ('requests', 'requests'),
    ]
    
    for module_name, display_name in required:
        try:
            __import__(module_name)
            hc.check(f"{display_name} installed", True)
        except ImportError:
            hc.check(
                f"{display_name} installed",
                False,
                f"Run: pip install {display_name}"
            )


def check_directories(hc):
    """Check directory structure"""
    print(f"\n[4/12] Directory Structure")
    
    required_dirs = [
        'backend',
        'backend/apps',
        'backend/apps/securebank',
        'backend/apps/shopvuln',
        'backend/owasp',
        'backend/utils',
        'scripts',
        'scripts/python',
    ]
    
    for directory in required_dirs:
        path = Path(directory)
        hc.check(
            f"{directory}/ exists",
            path.exists() and path.is_dir(),
            f"Directory not found: {directory}"
        )


def check_databases(hc):
    """Check database files"""
    print(f"\n[5/12] Database Files")
    
    databases = [
        ('backend/apps/securebank/securebank.db', 'SecureBank'),
        ('backend/apps/shopvuln/shopvuln.db', 'ShopVuln'),
    ]
    
    for db_path, name in databases:
        path = Path(db_path)
        hc.check(
            f"{name} database",
            path.exists() and path.is_file(),
            f"Run: python backend/apps/{name.lower()}/database.py" if 'SecureBank' in name 
            else f"Run: python backend/apps/shopvuln/database.py"
        )


def check_port_availability(hc):
    """Check if required ports are available"""
    print(f"\n[6/12] Port Availability")
    
    ports = [
        (5000, 'SecureBank Red'),
        (5001, 'SecureBank Blue'),
        (5002, 'ShopVuln Red'),
        (5003, 'ShopVuln Blue'),
    ]
    
    for port, name in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        
        is_available = result != 0
        hc.check(
            f"Port {port} ({name})",
            is_available,
            f"Port is in use. Stop the service using it." if not is_available else "",
            warning=not is_available
        )


def check_disk_space(hc):
    """Check available disk space"""
    print(f"\n[7/12] Disk Space")
    
    try:
        if platform.system() == 'Windows':
            import ctypes
            free_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(os.getcwd()),
                None, None,
                ctypes.pointer(free_bytes)
            )
            free_gb = free_bytes.value / (1024**3)
        else:
            stat = os.statvfs(os.getcwd())
            free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
        
        print(f"  Available: {free_gb:.2f} GB")
        
        hc.check(
            "Disk space (3GB+ recommended)",
            free_gb >= 3.0,
            f"Only {free_gb:.2f} GB available",
            warning=True
        )
    except Exception as e:
        hc.check("Disk space check", False, str(e), warning=True)


def check_internet(hc):
    """Check internet connectivity"""
    print(f"\n[8/12] Internet Connection")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex(('8.8.8.8', 53))
        sock.close()
        
        hc.check(
            "Internet connectivity",
            result == 0,
            "No internet connection (optional but recommended)",
            warning=True
        )
    except Exception:
        hc.check(
            "Internet connectivity",
            False,
            "No internet connection (optional but recommended)",
            warning=True
        )


def check_git(hc):
    """Check if Git is installed"""
    print(f"\n[9/12] Git Installation")
    
    try:
        result = subprocess.run(
            ['git', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        version = result.stdout.strip() if result.returncode == 0 else ""
        print(f"  {version}")
        
        hc.check(
            "Git installed",
            result.returncode == 0,
            "Git not found (optional)",
            warning=True
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        hc.check(
            "Git installed",
            False,
            "Git not found (optional)",
            warning=True
        )


def check_documentation(hc):
    """Check if documentation files exist"""
    print(f"\n[10/12] Documentation Files")
    
    docs = [
        'README_NEW.md',
        'QUICKSTART.md',
        'ROADMAP.md',
    ]
    
    found_count = 0
    for doc in docs:
        if Path(doc).exists():
            found_count += 1
    
    hc.check(
        f"Documentation ({found_count}/{len(docs)} files)",
        found_count >= 2,
        "Some documentation missing",
        warning=True
    )


def check_memory(hc):
    """Check available memory"""
    print(f"\n[11/12] System Memory")
    
    try:
        if platform.system() == 'Windows':
            import ctypes
            kernel32 = ctypes.windll.kernel32
            c_ulong = ctypes.c_ulong
            
            class MEMORYSTATUS(ctypes.Structure):
                _fields_ = [
                    ('dwLength', c_ulong),
                    ('dwMemoryLoad', c_ulong),
                    ('dwTotalPhys', c_ulong),
                    ('dwAvailPhys', c_ulong),
                    ('dwTotalPageFile', c_ulong),
                    ('dwAvailPageFile', c_ulong),
                    ('dwTotalVirtual', c_ulong),
                    ('dwAvailVirtual', c_ulong),
                ]
            
            memstatus = MEMORYSTATUS()
            memstatus.dwLength = ctypes.sizeof(MEMORYSTATUS)
            kernel32.GlobalMemoryStatus(ctypes.byref(memstatus))
            
            total_gb = memstatus.dwTotalPhys / (1024**3)
            avail_gb = memstatus.dwAvailPhys / (1024**3)
        else:
            # Linux/Mac
            import psutil
            mem = psutil.virtual_memory()
            total_gb = mem.total / (1024**3)
            avail_gb = mem.available / (1024**3)
        
        print(f"  Total: {total_gb:.2f} GB")
        print(f"  Available: {avail_gb:.2f} GB")
        
        hc.check(
            "RAM (4GB+ recommended)",
            total_gb >= 4.0,
            f"Only {total_gb:.2f} GB RAM",
            warning=True
        )
    except Exception as e:
        hc.check("Memory check", False, str(e), warning=True)


def check_browser(hc):
    """Check if a web browser is available"""
    print(f"\n[12/12] Web Browser")
    
    browsers = ['chrome', 'firefox', 'safari', 'msedge']
    browser_found = False
    
    if platform.system() == 'Windows':
        # Windows - check registry or common paths
        browser_found = True  # Assume browser exists on Windows
    else:
        # Linux/Mac - check if browser commands exist
        for browser in browsers:
            try:
                result = subprocess.run(
                    ['which', browser],
                    capture_output=True,
                    timeout=2
                )
                if result.returncode == 0:
                    browser_found = True
                    break
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
    
    hc.check(
        "Web browser available",
        browser_found,
        "No browser detected (optional)",
        warning=True
    )


def main():
    """Main health check routine"""
    print(f"\n{'='*60}")
    print(f"{Colors.BOLD}AegisForge System Health Check v2.0{Colors.END}")
    print(f"{'='*60}")
    
    hc = HealthCheck()
    
    # Run all checks
    check_python_version(hc)
    check_system_info(hc)
    check_dependencies(hc)
    check_directories(hc)
    check_databases(hc)
    check_port_availability(hc)
    check_disk_space(hc)
    check_internet(hc)
    check_git(hc)
    check_documentation(hc)
    check_memory(hc)
    check_browser(hc)
    
    # Print summary
    success = hc.print_summary()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
