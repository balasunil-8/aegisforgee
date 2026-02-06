"""
AegisForge Dual-Mode Architecture Framework
Manages switching between Red Team (vulnerable) and Blue Team (secure) modes
Version: 2.0
"""

import os
import sys
import subprocess
import signal
from enum import Enum
from typing import Optional, Dict, Any
import json
from datetime import datetime


class Mode(Enum):
    """AegisForge operating modes"""
    RED_TEAM = "red"
    BLUE_TEAM = "blue"
    COMPARISON = "comparison"


class AegisForgeManager:
    """
    Main manager for AegisForge dual-mode architecture
    Handles starting, stopping, and switching between modes
    """
    
    def __init__(self):
        self.current_mode: Optional[Mode] = None
        self.red_team_process: Optional[subprocess.Popen] = None
        self.blue_team_process: Optional[subprocess.Popen] = None
        self.red_team_port = 5000
        self.blue_team_port = 5001
        
    def start_red_team(self) -> bool:
        """Start Red Team (vulnerable) API"""
        try:
            print("🔴 Starting Red Team API (Vulnerable Endpoints)...")
            print(f"   Port: {self.red_team_port}")
            print("   ⚠️  WARNING: This mode contains intentional vulnerabilities")
            
            # Start the red team API
            self.red_team_process = subprocess.Popen(
                [sys.executable, 'aegisforge_api.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.current_mode = Mode.RED_TEAM
            print("✅ Red Team API started successfully")
            print(f"   Access at: http://localhost:{self.red_team_port}")
            return True
            
        except Exception as e:
            print(f"❌ Error starting Red Team API: {e}")
            return False
    
    def start_blue_team(self) -> bool:
        """Start Blue Team (secure) API"""
        try:
            print("🔵 Starting Blue Team API (Secure Endpoints)...")
            print(f"   Port: {self.blue_team_port}")
            print("   ✅ This mode demonstrates security best practices")
            
            # Start the blue team API
            self.blue_team_process = subprocess.Popen(
                [sys.executable, 'aegisforge_blue.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.current_mode = Mode.BLUE_TEAM
            print("✅ Blue Team API started successfully")
            print(f"   Access at: http://localhost:{self.blue_team_port}")
            return True
            
        except Exception as e:
            print(f"❌ Error starting Blue Team API: {e}")
            return False
    
    def start_comparison_mode(self) -> bool:
        """Start both Red and Blue team APIs for side-by-side comparison"""
        try:
            print("⚖️  Starting Comparison Mode (Both APIs)...")
            print("   This allows side-by-side comparison of vulnerable vs secure implementations")
            
            red_success = self.start_red_team()
            blue_success = self.start_blue_team()
            
            if red_success and blue_success:
                self.current_mode = Mode.COMPARISON
                print("✅ Comparison mode started successfully")
                print(f"   Red Team:  http://localhost:{self.red_team_port}")
                print(f"   Blue Team: http://localhost:{self.blue_team_port}")
                return True
            else:
                self.stop_all()
                return False
                
        except Exception as e:
            print(f"❌ Error starting Comparison mode: {e}")
            self.stop_all()
            return False
    
    def stop_red_team(self) -> bool:
        """Stop Red Team API"""
        try:
            if self.red_team_process:
                print("🛑 Stopping Red Team API...")
                self.red_team_process.terminate()
                self.red_team_process.wait(timeout=5)
                self.red_team_process = None
                print("✅ Red Team API stopped")
            return True
        except Exception as e:
            print(f"❌ Error stopping Red Team API: {e}")
            if self.red_team_process:
                self.red_team_process.kill()
                self.red_team_process = None
            return False
    
    def stop_blue_team(self) -> bool:
        """Stop Blue Team API"""
        try:
            if self.blue_team_process:
                print("🛑 Stopping Blue Team API...")
                self.blue_team_process.terminate()
                self.blue_team_process.wait(timeout=5)
                self.blue_team_process = None
                print("✅ Blue Team API stopped")
            return True
        except Exception as e:
            print(f"❌ Error stopping Blue Team API: {e}")
            if self.blue_team_process:
                self.blue_team_process.kill()
                self.blue_team_process = None
            return False
    
    def stop_all(self) -> bool:
        """Stop all running APIs"""
        print("🛑 Stopping all AegisForge services...")
        red_stopped = self.stop_red_team()
        blue_stopped = self.stop_blue_team()
        self.current_mode = None
        
        if red_stopped and blue_stopped:
            print("✅ All services stopped")
            return True
        return False
    
    def switch_mode(self, new_mode: Mode) -> bool:
        """Switch to a different mode"""
        print(f"🔄 Switching to {new_mode.value.upper()} mode...")
        
        # Stop current services
        self.stop_all()
        
        # Start new mode
        if new_mode == Mode.RED_TEAM:
            return self.start_red_team()
        elif new_mode == Mode.BLUE_TEAM:
            return self.start_blue_team()
        elif new_mode == Mode.COMPARISON:
            return self.start_comparison_mode()
        else:
            print(f"❌ Unknown mode: {new_mode}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of all services"""
        return {
            'current_mode': self.current_mode.value if self.current_mode else None,
            'red_team': {
                'running': self.red_team_process is not None and self.red_team_process.poll() is None,
                'port': self.red_team_port,
                'url': f'http://localhost:{self.red_team_port}'
            },
            'blue_team': {
                'running': self.blue_team_process is not None and self.blue_team_process.poll() is None,
                'port': self.blue_team_port,
                'url': f'http://localhost:{self.blue_team_port}'
            }
        }
    
    def print_status(self):
        """Print current status in a human-readable format"""
        status = self.get_status()
        
        print("\n" + "=" * 70)
        print("📊 AegisForge Status")
        print("=" * 70)
        print(f"Current Mode: {status['current_mode'] or 'STOPPED'}")
        print()
        print(f"🔴 Red Team API:")
        print(f"   Status: {'🟢 RUNNING' if status['red_team']['running'] else '🔴 STOPPED'}")
        print(f"   URL: {status['red_team']['url']}")
        print()
        print(f"🔵 Blue Team API:")
        print(f"   Status: {'🟢 RUNNING' if status['blue_team']['running'] else '🔴 STOPPED'}")
        print(f"   URL: {status['blue_team']['url']}")
        print("=" * 70 + "\n")


def print_banner():
    """Print AegisForge banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║   █████╗ ███████╗ ██████╗ ██╗███████╗███████╗ ██████╗ ██████╗   ║
    ║  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝██╔════╝██╔═══██╗██╔══██╗  ║
    ║  ███████║█████╗  ██║  ███╗██║███████╗█████╗  ██║   ██║██████╔╝  ║
    ║  ██╔══██║██╔══╝  ██║   ██║██║╚════██║██╔══╝  ██║   ██║██╔══██╗  ║
    ║  ██║  ██║███████╗╚██████╔╝██║███████║██║     ╚██████╔╝██║  ██║  ║
    ║  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝  ║
    ║                                                                   ║
    ║           Dual-Mode Security Testing Platform v2.0               ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_menu():
    """Print interactive menu"""
    print("\n📋 Available Commands:")
    print("  1. Start Red Team API (Vulnerable)")
    print("  2. Start Blue Team API (Secure)")
    print("  3. Start Comparison Mode (Both)")
    print("  4. Stop All Services")
    print("  5. Show Status")
    print("  6. Exit")
    print()


def interactive_mode():
    """Run AegisForge in interactive mode"""
    print_banner()
    manager = AegisForgeManager()
    
    # Register signal handler for clean shutdown
    def signal_handler(sig, frame):
        print("\n\n🛑 Shutting down AegisForge...")
        manager.stop_all()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    print("Welcome to AegisForge Dual-Mode Architecture!")
    print("This framework allows you to run and compare vulnerable and secure APIs.")
    
    try:
        while True:
            print_menu()
            choice = input("Enter your choice (1-6): ").strip()
            
            if choice == '1':
                manager.stop_all()
                manager.start_red_team()
            elif choice == '2':
                manager.stop_all()
                manager.start_blue_team()
            elif choice == '3':
                manager.stop_all()
                manager.start_comparison_mode()
            elif choice == '4':
                manager.stop_all()
            elif choice == '5':
                manager.print_status()
            elif choice == '6':
                print("👋 Exiting AegisForge...")
                manager.stop_all()
                break
            else:
                print("❌ Invalid choice. Please enter 1-6.")
    
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down AegisForge...")
        manager.stop_all()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        manager.stop_all()


def cli_mode():
    """Run AegisForge from command line arguments"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='AegisForge Dual-Mode Security Testing Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python aegisforge_modes.py red        # Start red team (vulnerable) API
  python aegisforge_modes.py blue       # Start blue team (secure) API
  python aegisforge_modes.py compare    # Start both APIs for comparison
  python aegisforge_modes.py status     # Show current status
  python aegisforge_modes.py stop       # Stop all services
        """
    )
    
    parser.add_argument(
        'command',
        nargs='?',
        choices=['red', 'blue', 'compare', 'status', 'stop', 'interactive'],
        default='interactive',
        help='Command to execute'
    )
    
    args = parser.parse_args()
    
    manager = AegisForgeManager()
    
    if args.command == 'red':
        print_banner()
        manager.start_red_team()
        try:
            # Keep running until interrupted
            signal.pause()
        except KeyboardInterrupt:
            print("\n🛑 Stopping Red Team API...")
            manager.stop_all()
    
    elif args.command == 'blue':
        print_banner()
        manager.start_blue_team()
        try:
            signal.pause()
        except KeyboardInterrupt:
            print("\n🛑 Stopping Blue Team API...")
            manager.stop_all()
    
    elif args.command == 'compare':
        print_banner()
        manager.start_comparison_mode()
        try:
            signal.pause()
        except KeyboardInterrupt:
            print("\n🛑 Stopping all services...")
            manager.stop_all()
    
    elif args.command == 'status':
        manager.print_status()
    
    elif args.command == 'stop':
        manager.stop_all()
    
    elif args.command == 'interactive':
        interactive_mode()


if __name__ == '__main__':
    cli_mode()
AegisForge Mode Switching Module
Manages Red Team (offensive) vs Blue Team (defensive) modes
"""

from flask import session
from enum import Enum

class SecurityMode(Enum):
    RED_TEAM = "red"    # Vulnerable endpoints for exploitation practice
    BLUE_TEAM = "blue"  # Hardened endpoints showing security best practices

# Default mode
DEFAULT_MODE = SecurityMode.RED_TEAM

def get_current_mode():
    """Get the current security mode from session"""
    mode_str = session.get('security_mode', DEFAULT_MODE.value)
    try:
        return SecurityMode(mode_str)
    except ValueError:
        return DEFAULT_MODE

def set_mode(mode: SecurityMode):
    """Set the security mode in session"""
    session['security_mode'] = mode.value
    session.modified = True

def toggle_mode():
    """Toggle between Red Team and Blue Team modes"""
    current = get_current_mode()
    new_mode = SecurityMode.BLUE_TEAM if current == SecurityMode.RED_TEAM else SecurityMode.RED_TEAM
    set_mode(new_mode)
    return new_mode

def is_red_team_mode():
    """Check if currently in Red Team (vulnerable) mode"""
    return get_current_mode() == SecurityMode.RED_TEAM

def is_blue_team_mode():
    """Check if currently in Blue Team (hardened) mode"""
    return get_current_mode() == SecurityMode.BLUE_TEAM

def get_mode_info():
    """Get information about the current mode"""
    mode = get_current_mode()
    
    if mode == SecurityMode.RED_TEAM:
        return {
            'mode': 'red',
            'name': 'Red Team',
            'description': 'Offensive Security - Vulnerable endpoints for exploitation practice',
            'color': '#DC2626',
            'icon': '🔴',
            'purpose': 'Learn to identify and exploit vulnerabilities'
        }
    else:
        return {
            'mode': 'blue',
            'name': 'Blue Team',
            'description': 'Defensive Security - Hardened endpoints with security controls',
            'color': '#1E40AF',
            'icon': '🔵',
            'purpose': 'Learn security best practices and defensive techniques'
        }
