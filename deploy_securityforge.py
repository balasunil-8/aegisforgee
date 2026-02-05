#!/usr/bin/env python3
"""
SecurityForge Quick Deployment Tool
Run this to deploy SecurityForge to your chosen platform in minutes
"""

import os
import sys
import json
from pathlib import Path

def print_header():
    print("\n" + "="*70)
    print("🚀 SECURITYFORGE DEPLOYMENT WIZARD")
    print("="*70 + "\n")

def print_options():
    print("Choose your deployment option:\n")
    options = {
        "1": ("Local Development", "python securityforge_api.py", "1 min"),
        "2": ("Docker (Local)", "docker-compose -f docker-compose.production.yml up", "2 min"),
        "3": ("Railway.app (Cloud)", "Browser-based deployment", "5 min"),
        "4": ("Render.com (Cloud)", "Browser-based deployment", "5 min"),
        "5": ("Heroku (Legacy Cloud)", "CLI-based deployment", "3 min"),
        "6": ("View Deployment Guide", "Open SECURITYFORGE_DEPLOYMENT_GUIDE.md", "Read"),
        "7": ("Quick Test (13 tests)", "python quick_test_vulnerabilities.py", "2 min"),
    }
    
    for num, (name, cmd, time) in options.items():
        print(f"{num}. {name:30} [{time:6}]")
    
    return options

def deployment_local():
    print("\n" + "-"*70)
    print("LOCAL DEVELOPMENT DEPLOYMENT")
    print("-"*70 + "\n")
    print("Starting SecurityForge API...\n")
    print("Command: python securityforge_api.py\n")
    print("Your API will be available at:")
    print("  • Local:   http://localhost:5000")
    print("  • Network: http://192.168.x.x:5000\n")
    print("Quick test:")
    print("  curl http://localhost:5000/api/health\n")
    print("Test all vulnerabilities:")
    print("  python quick_test_vulnerabilities.py\n")
    
    response = input("Start SecurityForge API now? (y/n): ").lower()
    if response == 'y':
        os.system("python securityforge_api.py")

def deployment_docker():
    print("\n" + "-"*70)
    print("DOCKER DEPLOYMENT")
    print("-"*70 + "\n")
    
    # Check if Docker is installed
    result = os.system("docker --version > nul 2>&1")
    if result != 0:
        print("❌ Docker is not installed!")
        print("Install from: https://www.docker.com/products/docker-desktop")
        return
    
    print("✓ Docker detected\n")
    print("Starting SecurityForge with Docker Compose...\n")
    print("This will:")
    print("  • Start SecurityForge API (port 5000)")
    print("  • Start PostgreSQL database (port 5432)")
    print("  • Setup Adminer database UI (port 8080)\n")
    
    response = input("Deploy with Docker Compose? (y/n): ").lower()
    if response == 'y':
        os.system("docker-compose -f docker-compose.production.yml up -d")
        print("\n✓ Deployment started!")
        print("  API:     http://localhost:5000")
        print("  Adminer: http://localhost:8080")
        print("\nCheck status: docker-compose -f docker-compose.production.yml logs -f api")

def deployment_railway():
    print("\n" + "-"*70)
    print("RAILWAY.APP DEPLOYMENT (Recommended - Easiest)")
    print("-"*70 + "\n")
    print("Railroad.app makes cloud deployment simple:\n")
    print("Steps:")
    print("1. Go to https://railway.app (create free account)")
    print("2. Connect your GitHub repository")
    print("3. Add environment variables:")
    print("   • FLASK_ENV=production")
    print("   • SECRET_KEY=[generate random 40+ char string]")
    print("   • JWT_SECRET_KEY=[generate random 40+ char string]")
    print("4. Click 'Deploy'")
    print("\n✓ Your API is live in 2-3 minutes!\n")
    
    print("For detailed steps, see:")
    print("  SECURITYFORGE_DEPLOYMENT_GUIDE.md → Option 1: Railway.app\n")
    
    response = input("Open Railway.app in browser? (y/n): ").lower()
    if response == 'y':
        import webbrowser
        webbrowser.open("https://railway.app")

def deployment_render():
    print("\n" + "-"*70)
    print("RENDER.COM DEPLOYMENT")
    print("-"*70 + "\n")
    print("Render.com offers easy free tier deployment:\n")
    print("Steps:")
    print("1. Go to https://render.com (create free account)")
    print("2. Create New → Web Service")
    print("3. Connect GitHub repository")
    print("4. Configure:")
    print("   • Runtime: Python 3.11")
    print("   • Build Command: pip install -r requirements_securityforge.txt")
    print("   • Start Command: gunicorn -w 4 -b 0.0.0.0:5000 securityforge_api:app")
    print("5. Add environment variables (SECRET_KEY, JWT_SECRET_KEY, etc.)")
    print("6. Deploy\n")
    
    print("For detailed steps, see:")
    print("  SECURITYFORGE_DEPLOYMENT_GUIDE.md → Option 2: Render.com\n")
    
    response = input("Open Render.com in browser? (y/n): ").lower()
    if response == 'y':
        import webbrowser
        webbrowser.open("https://render.com")

def deployment_guide():
    print("\n" + "-"*70)
    print("DEPLOYMENT GUIDE")
    print("-"*70 + "\n")
    
    guide_file = "SECURITYFORGE_DEPLOYMENT_GUIDE.md"
    if os.path.exists(guide_file):
        print(f"Opening {guide_file}...\n")
        
        # Try to open with default viewer
        import platform
        if platform.system() == 'Windows':
            os.system(f"start {guide_file}")
        elif platform.system() == 'Darwin':  # macOS
            os.system(f"open {guide_file}")
        else:  # Linux
            os.system(f"xdg-open {guide_file}")
    else:
        print(f"❌ {guide_file} not found!")

def quick_test():
    print("\n" + "-"*70)
    print("QUICK VULNERABILITY TEST (13 Tests)")
    print("-"*70 + "\n")
    print("This will:")
    print("  • Initialize test database")
    print("  • Test all 9 vulnerable endpoints")
    print("  • Verify exploitation techniques")
    print("  • Generate test report\n")
    
    response = input("Run quick test now? (y/n): ").lower()
    if response == 'y':
        os.system("python quick_test_vulnerabilities.py")

def main():
    print_header()
    options = print_options()
    
    choice = input("\nSelect option (1-7): ").strip()
    
    if choice == "1":
        deployment_local()
    elif choice == "2":
        deployment_docker()
    elif choice == "3":
        deployment_railway()
    elif choice == "4":
        deployment_render()
    elif choice == "5":
        deployment_guide()
    elif choice == "6":
        deployment_guide()
    elif choice == "7":
        quick_test()
    else:
        print("\n❌ Invalid option")
        main()

def quickstart():
    """Quick deployment comparison"""
    print("\n" + "="*70)
    print("DEPLOYMENT COMPARISON")
    print("="*70 + "\n")
    
    comparison = """
    Method          | Time  | Cost   | Effort | Recommended For
    ────────────────┼───────┼────────┼────────┼──────────────────────────
    Local Dev       | 30s   | $0     | ⭐     | Testing & learning
    Docker Local    | 2min  | $0     | ⭐⭐   | Production locally
    Railway.app     | 5min  | Free   | ⭐     | Cloud deployment (EASY!)
    Render.com      | 5min  | Free   | ⭐⭐   | Cloud deployment
    Heroku          | 3min  | $$     | ⭐⭐   | Legacy cloud (paid)
    AWS EB          | 10min | $$$$   | ⭐⭐⭐ | Enterprise deployments
    
    🏆 RECOMMENDED: Railway.app (5 minutes, free, easiest!)
    """
    print(comparison)

if __name__ == '__main__':
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--compare":
            quickstart()
        else:
            main()
    except KeyboardInterrupt:
        print("\n\n👋 Deployment wizard closed.\n")
        sys.exit(0)
