#!/usr/bin/env python3
"""
VulnShop API - Integrated Startup Script
Automatically starts the API backend and opens the dashboard in browser
"""

import os
import sys
import time
import webbrowser
import subprocess
import signal
from pathlib import Path
import platform

# ANSI Color codes for nice terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header():
    """Print a stylized header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}")
    print("╔═════════════════════════════════════════════════════════════════════════╗")
    print("║                   🔒 VulnShop API - Integrated Launcher                ║")
    print("║              OWASP API Top 10 (2023) Educational Lab                   ║")
    print("╚═════════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.ENDC}\n")

def print_status(message, status="INFO"):
    """Print a formatted status message"""
    if status == "SUCCESS":
        color = Colors.OKGREEN
        symbol = "✓"
    elif status == "ERROR":
        color = Colors.FAIL
        symbol = "✗"
    elif status == "WARNING":
        color = Colors.WARNING
        symbol = "⚠"
    elif status == "INFO":
        color = Colors.OKCYAN
        symbol = "ℹ"
    else:
        color = Colors.OKBLUE
        symbol = "→"
    
    print(f"{color}{symbol} {message}{Colors.ENDC}")

def check_python_version():
    """Ensure Python 3.8+"""
    if sys.version_info < (3, 8):
        print_status(f"Python {sys.version_info.major}.{sys.version_info.minor} detected (requires 3.8+)", "ERROR")
        sys.exit(1)
    print_status(f"Python {sys.version_info.major}.{sys.version_info.minor} ✓", "SUCCESS")

def check_venv():
    """Check if running in virtual environment"""
    if sys.prefix == sys.base_prefix:
        print_status("Not running in virtual environment", "WARNING")
        print_status("Virtual environment recommended. Activate with:", "INFO")
        if platform.system() == "Windows":
            print(f"  {Colors.OKBLUE}.venv\\Scripts\\Activate.ps1{Colors.ENDC}")
        else:
            print(f"  {Colors.OKBLUE}source .venv/bin/activate{Colors.ENDC}")
        response = input("\nContinue anyway? (y/n): ").strip().lower()
        if response != 'y':
            print_status("Startup cancelled", "WARNING")
            sys.exit(0)
    else:
        print_status("Virtual environment active ✓", "SUCCESS")

def check_dependencies():
    """Check if required packages are installed"""
    required_packages = {
        'flask': 'Flask',
        'flask_cors': 'Flask-CORS',
        'flask_sqlalchemy': 'Flask-SQLAlchemy',
        'flask_jwt_extended': 'Flask-JWT-Extended',
        'requests': 'requests'
    }
    
    missing = []
    for import_name, package_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package_name)
    
    if missing:
        print_status(f"Missing packages: {', '.join(missing)}", "ERROR")
        print_status("Install with: pip install -r requirements.txt", "INFO")
        sys.exit(1)
    
    print_status(f"All {len(required_packages)} required packages installed ✓", "SUCCESS")

def check_dashboard_file():
    """Check if Dashboard_Interactive.html exists"""
    if not Path("Dashboard_Interactive.html").exists():
        print_status("Dashboard_Interactive.html not found in current directory", "ERROR")
        sys.exit(1)
    print_status("Dashboard file found ✓", "SUCCESS")

def start_backend():
    """Start the Flask backend server"""
    print_status("Starting VulnShop API backend...", "INFO")
    
    # Use Python to run vulnshop.py in current process
    # We'll exec it which will block, so we need subprocess instead
    # Actually, let's run it as subprocess in background
    
    try:
        # Start the Flask app
        from vulnshop import app
        
        print_status("Initializing database...", "INFO")
        with app.app_context():
            from vulnshop import seed_data
            seed_data()
        
        print_status("Database initialized ✓", "SUCCESS")
        print_status(f"Backend will start on {Colors.BOLD}http://localhost:5000{Colors.ENDC}", "SUCCESS")
        
        return app
    except Exception as e:
        print_status(f"Failed to initialize app: {e}", "ERROR")
        sys.exit(1)

def wait_for_api(timeout=10):
    """Wait for API to become responsive"""
    import requests
    start_time = time.time()
    
    print_status("Waiting for API to respond...", "INFO")
    
    while time.time() - start_time < timeout:
        try:
            response = requests.get("http://localhost:5000/api/health", timeout=1)
            if response.status_code == 200:
                print_status("API is online and responding ✓", "SUCCESS")
                return True
        except requests.exceptions.RequestException:
            time.sleep(0.5)
    
    print_status(f"API did not respond within {timeout} seconds", "ERROR")
    return False

def open_dashboard():
    """Open the dashboard in the default browser"""
    dashboard_url = "http://localhost:5000/"
    print_status(f"Opening dashboard at {Colors.BOLD}{dashboard_url}{Colors.ENDC}", "INFO")
    
    try:
        webbrowser.open(dashboard_url)
        time.sleep(1)
        print_status("Dashboard opened in browser ✓", "SUCCESS")
    except Exception as e:
        print_status(f"Could not open browser: {e}", "WARNING")
        print_status(f"Manually visit: {dashboard_url}", "INFO")

def print_instructions():
    """Print usage instructions"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}")
    print("╔═════════════════════════════════════════════════════════════════════════╗")
    print("║                       🎯 Quick Start Guide                              ║")
    print("╚═════════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}📊 Dashboard:{Colors.ENDC}")
    print(f"  The dashboard should open automatically in your browser")
    print(f"  If not, visit: {Colors.OKBLUE}http://localhost:5000/{Colors.ENDC}\n")
    
    print(f"{Colors.BOLD}🧪 Postman Testing:{Colors.ENDC}")
    print(f"  1. Open Postman")
    print(f"  2. Import: {Colors.OKBLUE}VulnShop_Collection.json{Colors.ENDC}")
    print(f"  3. Import Environment: {Colors.OKBLUE}VulnShop_Environment.json{Colors.ENDC}")
    print(f"  4. Start testing the vulnerabilities\n")
    
    print(f"{Colors.BOLD}📚 Tabs in Dashboard:{Colors.ENDC}")
    print(f"  • {Colors.OKCYAN}Live Backend Data{Colors.ENDC}     - View real database contents")
    print(f"  • {Colors.OKCYAN}Postman Test Guide{Colors.ENDC}  - Detailed test explanations")
    print(f"  • {Colors.OKCYAN}OWASP Vulnerabilities{Colors.ENDC} - Vulnerability reference")
    print(f"  • {Colors.OKCYAN}Attack Demonstrations{Colors.ENDC} - Step-by-step attack guides")
    print(f"  • {Colors.OKCYAN}Teaching Guide{Colors.ENDC}      - Classroom lesson plans\n")
    
    print(f"{Colors.BOLD}🔒 Secure Version:{Colors.ENDC}")
    print(f"  Compare vulnerable vs fixed code:")
    print(f"  {Colors.OKBLUE}python secure_vulnshop.py{Colors.ENDC}\n")
    
    print(f"{Colors.BOLD}📊 Generate Report:{Colors.ENDC}")
    print(f"  {Colors.OKBLUE}python generate_report.py{Colors.ENDC}\n")
    
    print(f"{Colors.BOLD}🛑 Stop the Backend:{Colors.ENDC}")
    print(f"  Press {Colors.WARNING}Ctrl+C{Colors.ENDC} in this terminal\n")
    
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("╚═════════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.ENDC}\n")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\n\n{Colors.WARNING}Shutting down VulnShop API...{Colors.ENDC}")
    sys.exit(0)

def main():
    """Main startup sequence"""
    print_header()
    
    # Check prerequisites
    print(f"{Colors.BOLD}Checking Prerequisites...{Colors.ENDC}\n")
    check_python_version()
    check_venv()
    check_dependencies()
    check_dashboard_file()
    
    print()
    
    # Start backend
    print(f"{Colors.BOLD}Starting Backend...{Colors.ENDC}\n")
    app = start_backend()
    
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Open browser after short delay
    print()
    
    # Start Flask in a separate thread so we can wait and open browser
    import threading
    flask_thread = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False),
        daemon=False
    )
    flask_thread.start()
    
    # Wait for API to be ready
    time.sleep(2)
    if wait_for_api(timeout=10):
        open_dashboard()
    
    # Print instructions
    print_instructions()
    
    print(f"{Colors.OKGREEN}{Colors.BOLD}✓ VulnShop API is running!{Colors.ENDC}")
    print(f"{Colors.OKCYAN}Press Ctrl+C to stop{Colors.ENDC}\n")
    
    # Keep the script running
    try:
        flask_thread.join()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Shutdown signal received{Colors.ENDC}")
        sys.exit(0)

if __name__ == "__main__":
    main()
