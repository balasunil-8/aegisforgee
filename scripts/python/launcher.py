#!/usr/bin/env python3
"""
AegisForge Interactive Launcher
Simple menu-driven interface to start/stop applications
Version 2.0
"""

import sys
import os
import subprocess
import time
import signal
import platform
from pathlib import Path


class ApplicationLauncher:
    """Interactive application launcher"""
    
    APPLICATIONS = {
        '1': {
            'name': 'SecureBank Red Team',
            'script': 'backend/apps/securebank/securebank_red_api.py',
            'port': 5000,
            'url': 'http://localhost:5000',
            'process': None
        },
        '2': {
            'name': 'SecureBank Blue Team',
            'script': 'backend/apps/securebank/securebank_blue_api.py',
            'port': 5001,
            'url': 'http://localhost:5001',
            'process': None
        },
        '3': {
            'name': 'ShopVuln Red Team',
            'script': 'backend/apps/shopvuln/shopvuln_red_api.py',
            'port': 5002,
            'url': 'http://localhost:5002',
            'process': None
        },
        '4': {
            'name': 'ShopVuln Blue Team',
            'script': 'backend/apps/shopvuln/shopvuln_blue_api.py',
            'port': 5003,
            'url': 'http://localhost:5003',
            'process': None
        },
    }
    
    def __init__(self):
        self.running_processes = {}
    
    def print_banner(self):
        """Print launcher banner"""
        print("\n" + "="*60)
        print("  🛡️  AegisForge Interactive Launcher v2.0")
        print("="*60 + "\n")
    
    def print_menu(self):
        """Print main menu"""
        print("\n" + "-"*60)
        print("Main Menu")
        print("-"*60 + "\n")
        
        print("🚀 Start Applications:")
        for key, app in self.APPLICATIONS.items():
            status = "✅ RUNNING" if app['process'] and app['process'].poll() is None else "⭕ STOPPED"
            print(f"  [{key}] {app['name']} (Port {app['port']}) - {status}")
        
        print(f"\n  [5] Start ALL Applications")
        
        print("\n🛑 Stop Applications:")
        print("  [6] Stop ALL Applications")
        
        print("\n🔧 Management:")
        print("  [7] Check Status")
        print("  [8] Run Health Check")
        print("  [9] Initialize Databases")
        
        print("\n  [0] Exit")
        print("\n" + "-"*60)
    
    def start_application(self, app_key):
        """Start a single application"""
        if app_key not in self.APPLICATIONS:
            print("❌ Invalid application key")
            return False
        
        app = self.APPLICATIONS[app_key]
        
        # Check if already running
        if app['process'] and app['process'].poll() is None:
            print(f"⚠️  {app['name']} is already running")
            return True
        
        # Check if script exists
        script_path = Path(app['script'])
        if not script_path.exists():
            print(f"❌ Script not found: {script_path}")
            return False
        
        print(f"\n🚀 Starting {app['name']}...")
        print(f"   Port: {app['port']}")
        print(f"   URL: {app['url']}")
        
        try:
            # Start the process
            process = subprocess.Popen(
                [sys.executable, str(script_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            app['process'] = process
            self.running_processes[app_key] = process
            
            # Wait a moment to see if it starts successfully
            time.sleep(2)
            
            if process.poll() is None:
                print(f"✅ {app['name']} started successfully (PID: {process.pid})")
                print(f"   Access at: {app['url']}")
                return True
            else:
                print(f"❌ {app['name']} failed to start")
                stdout, stderr = process.communicate(timeout=1)
                if stderr:
                    print(f"   Error: {stderr[:200]}")
                return False
                
        except Exception as e:
            print(f"❌ Failed to start {app['name']}: {e}")
            return False
    
    def start_all_applications(self):
        """Start all applications"""
        print("\n🚀 Starting all applications...\n")
        
        success_count = 0
        for key in self.APPLICATIONS.keys():
            if self.start_application(key):
                success_count += 1
                time.sleep(1)  # Stagger starts
        
        print(f"\n✅ Started {success_count}/{len(self.APPLICATIONS)} applications")
        
        if success_count > 0:
            print("\n🌐 Opening browsers...")
            time.sleep(2)
            for key, app in self.APPLICATIONS.items():
                if app['process'] and app['process'].poll() is None:
                    self.open_browser(app['url'])
                    time.sleep(0.5)
    
    def stop_application(self, app_key):
        """Stop a single application"""
        if app_key not in self.APPLICATIONS:
            return False
        
        app = self.APPLICATIONS[app_key]
        
        if not app['process'] or app['process'].poll() is not None:
            print(f"⚠️  {app['name']} is not running")
            return True
        
        print(f"\n🛑 Stopping {app['name']}...")
        
        try:
            # Send termination signal
            app['process'].terminate()
            
            # Wait for graceful shutdown
            try:
                app['process'].wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Force kill if doesn't stop
                app['process'].kill()
                app['process'].wait()
            
            app['process'] = None
            if app_key in self.running_processes:
                del self.running_processes[app_key]
            
            print(f"✅ {app['name']} stopped")
            return True
            
        except Exception as e:
            print(f"❌ Failed to stop {app['name']}: {e}")
            return False
    
    def stop_all_applications(self):
        """Stop all running applications"""
        print("\n🛑 Stopping all applications...\n")
        
        stopped_count = 0
        for key in self.APPLICATIONS.keys():
            if self.stop_application(key):
                stopped_count += 1
        
        print(f"\n✅ Stopped {stopped_count} applications")
    
    def check_status(self):
        """Check status of all applications"""
        print("\n" + "="*60)
        print("Application Status")
        print("="*60 + "\n")
        
        for key, app in self.APPLICATIONS.items():
            if app['process'] and app['process'].poll() is None:
                status = f"✅ RUNNING (PID: {app['process'].pid})"
            else:
                status = "⭕ STOPPED"
            
            print(f"{app['name']}")
            print(f"  Port: {app['port']}")
            print(f"  URL: {app['url']}")
            print(f"  Status: {status}")
            print()
    
    def run_health_check(self):
        """Run system health check"""
        print("\n🔬 Running health check...\n")
        
        health_check_script = Path('scripts/python/health_check.py')
        
        if not health_check_script.exists():
            print("❌ Health check script not found")
            return
        
        try:
            subprocess.run([sys.executable, str(health_check_script)])
        except Exception as e:
            print(f"❌ Health check failed: {e}")
    
    def initialize_databases(self):
        """Initialize databases"""
        print("\n🔨 Initializing databases...\n")
        
        db_manager_script = Path('scripts/python/database_manager.py')
        
        if not db_manager_script.exists():
            print("❌ Database manager script not found")
            return
        
        try:
            subprocess.run([sys.executable, str(db_manager_script), 'reset'])
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
    
    def open_browser(self, url):
        """Open URL in default browser"""
        try:
            if platform.system() == 'Darwin':  # macOS
                subprocess.run(['open', url], check=False)
            elif platform.system() == 'Windows':
                subprocess.run(['start', url], shell=True, check=False)
            else:  # Linux
                subprocess.run(['xdg-open', url], check=False)
        except Exception:
            pass  # Silently fail if can't open browser
    
    def cleanup(self):
        """Cleanup running processes on exit"""
        print("\n🧹 Cleaning up...")
        for key in list(self.APPLICATIONS.keys()):
            if self.APPLICATIONS[key]['process']:
                self.stop_application(key)
    
    def run(self):
        """Main launcher loop"""
        self.print_banner()
        
        print("Welcome to AegisForge!")
        print("\nTest Credentials:")
        print("  Username: admin")
        print("  Password: admin123\n")
        
        try:
            while True:
                self.print_menu()
                
                choice = input("\nEnter your choice: ").strip()
                
                if choice == '0':
                    print("\n👋 Exiting...")
                    break
                
                elif choice in ['1', '2', '3', '4']:
                    self.start_application(choice)
                
                elif choice == '5':
                    self.start_all_applications()
                
                elif choice == '6':
                    self.stop_all_applications()
                
                elif choice == '7':
                    self.check_status()
                
                elif choice == '8':
                    self.run_health_check()
                
                elif choice == '9':
                    self.initialize_databases()
                
                else:
                    print("\n❌ Invalid choice. Please try again.")
                
                input("\nPress Enter to continue...")
        
        except KeyboardInterrupt:
            print("\n\n⚠️  Interrupted by user")
        
        finally:
            self.cleanup()
        
        print("\n✅ Goodbye!\n")


def main():
    """Main entry point"""
    # Change to project root directory
    script_dir = Path(__file__).parent.parent.parent
    if script_dir.exists():
        os.chdir(script_dir)
    
    launcher = ApplicationLauncher()
    launcher.run()


if __name__ == '__main__':
    main()
