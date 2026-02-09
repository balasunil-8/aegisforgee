# 🛡️ AegisForge Installation Guide

This guide covers installation and setup for AegisForge on Windows, Linux, and macOS.

## 📋 Prerequisites

### Required Software
- **Python 3.8+** (3.10+ recommended)
- **pip** (Python package manager)
- **Git** (for cloning the repository)
- **PostgreSQL** (optional, SQLite used by default)
- **Redis** (optional, for advanced features)

### Recommended Tools
- **Docker & Docker Compose** (for containerized deployment)
- **Postman** (for API testing)
- **OWASP ZAP** or **Burp Suite** (for security testing)

---

## 🪟 Windows Installation

### Method 1: Standard Installation

#### Step 1: Install Python
```powershell
# Download Python from python.org (3.10+ recommended)
# Ensure "Add Python to PATH" is checked during installation

# Verify installation
python --version
pip --version
```

#### Step 2: Clone Repository
```powershell
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
```

#### Step 3: Create Virtual Environment
```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\activate
```

#### Step 4: Install Dependencies
```powershell
# Install core dependencies
pip install -r requirements.txt

# For production features (optional)
pip install -r requirements_pro.txt
```

#### Step 5: Configure Environment
```powershell
# Copy example environment file
copy .env.example .env

# Edit .env with your configuration (use notepad or any text editor)
notepad .env
```

#### Step 6: Initialize Database
```powershell
python init_db.py
```

#### Step 7: Start Application
```powershell
# Using the provided launcher
.\LaunchSecurityForge.bat

# Or manually
python aegisforge_api.py
```

### Method 2: Docker Installation (Recommended)

```powershell
# Clone repository
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee

# Start with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f
```

---

## 🐧 Linux Installation

### Method 1: Standard Installation

#### Step 1: Update System & Install Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git postgresql redis-server

# CentOS/RHEL
sudo yum install -y python3 python3-pip git postgresql-server redis

# Arch Linux
sudo pacman -S python python-pip git postgresql redis
```

#### Step 2: Clone Repository
```bash
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
```

#### Step 3: Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

#### Step 4: Install Dependencies
```bash
# Install core dependencies
pip install -r requirements.txt

# For production features (optional)
pip install -r requirements_pro.txt
```

#### Step 5: Configure Environment
```bash
# Copy example environment file
cp .env.example .env

# Edit with your preferred editor
nano .env  # or vim, gedit, etc.
```

#### Step 6: Initialize Database
```bash
python init_db.py
```

#### Step 7: Start Application
```bash
# Using the provided launcher
chmod +x start_pentestlab.sh
./start_pentestlab.sh

# Or manually
python aegisforge_api.py
```

### Method 2: Docker Installation (Recommended)

```bash
# Clone repository
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee

# Start with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

---

## 🍎 macOS Installation

### Method 1: Standard Installation

#### Step 1: Install Homebrew (if not installed)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Step 2: Install Dependencies
```bash
# Install Python, Git, PostgreSQL, and Redis
brew install python@3.10 git postgresql@14 redis

# Start services (optional)
brew services start postgresql@14
brew services start redis
```

#### Step 3: Clone Repository
```bash
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
```

#### Step 4: Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

#### Step 5: Install Dependencies
```bash
# Install core dependencies
pip install -r requirements.txt

# For production features (optional)
pip install -r requirements_pro.txt
```

#### Step 6: Configure Environment
```bash
# Copy example environment file
cp .env.example .env

# Edit with your preferred editor
nano .env  # or vim, TextEdit, etc.
```

#### Step 7: Initialize Database
```bash
python init_db.py
```

#### Step 8: Start Application
```bash
# Using the provided launcher
chmod +x start_pentestlab.sh
./start_pentestlab.sh

# Or manually
python aegisforge_api.py
```

### Method 2: Docker Installation (Recommended)

```bash
# Install Docker Desktop for Mac from docker.com
# Then:

git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee

docker-compose up -d
docker-compose logs -f
```

---

## 🔧 Configuration

### Environment Variables (.env file)

```bash
# Flask Configuration
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DEBUG=True

# Database Configuration (optional - defaults to SQLite)
DATABASE_URL=sqlite:///instance/aegisforge.db
# For PostgreSQL:
# DATABASE_URL=postgresql://user:password@localhost/aegisforge

# Redis Configuration (optional)
REDIS_URL=redis://localhost:6379/0

# JWT Configuration
JWT_SECRET_KEY=your-jwt-secret-key

# Security Settings
RATE_LIMIT_ENABLED=True
CORS_ENABLED=True

# CTF Configuration
CTF_MODE=True
LEADERBOARD_ENABLED=True

# AI Detection (optional)
AI_DETECTION_ENABLED=False
```

### Database Setup

#### SQLite (Default)
No additional configuration needed. Database is created automatically in `instance/` directory.

#### PostgreSQL (Production)
```bash
# Create database
createdb aegisforge

# Update .env file
DATABASE_URL=postgresql://username:password@localhost/aegisforge

# Initialize database
python init_db.py
```

---

## 🚀 Verification

### Test Installation

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\activate   # Windows

# Run basic endpoint test
python test_endpoints.py

# Check API health
curl http://localhost:5000/api/health
```

### Access the Application

- **API Base URL**: http://localhost:5000
- **Dashboard**: http://localhost:5000/dashboard (if available)
- **API Documentation**: http://localhost:5000/api/docs

### Run CTF Challenges

```bash
# Start CTF mode
python ctf_manager.py

# View leaderboard
curl http://localhost:5000/api/leaderboard
```

---

## 🔍 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Error: Address already in use - Port 5000

# Solution 1: Kill process using port
# Linux/macOS
lsof -ti:5000 | xargs kill -9

# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Solution 2: Change port in config
export FLASK_RUN_PORT=8000  # Linux/macOS
set FLASK_RUN_PORT=8000     # Windows
```

#### Python Version Issues
```bash
# Error: Python version too old

# Verify version
python --version

# Install correct version
# Windows: Download from python.org
# Linux: sudo apt install python3.10
# macOS: brew install python@3.10

# Use specific version
python3.10 -m venv venv
```

#### Import Errors
```bash
# Error: ModuleNotFoundError

# Ensure virtual environment is activated
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\activate   # Windows

# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

#### Database Connection Errors
```bash
# Error: Could not connect to database

# SQLite: Check file permissions on instance/ directory
chmod 755 instance/
chmod 644 instance/aegisforge.db

# PostgreSQL: Verify service is running
sudo service postgresql status  # Linux
brew services list              # macOS
```

#### Permission Denied Errors
```bash
# Linux/macOS: Make scripts executable
chmod +x start_pentestlab.sh
chmod +x LaunchSecurityForge.ps1

# Windows: Run PowerShell as Administrator
```

#### SSL/TLS Certificate Errors
```bash
# Error: SSL certificate verification failed

# Temporary fix (not recommended for production)
export CURL_CA_BUNDLE=""
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

#### Redis Connection Errors
```bash
# Error: Redis connection failed

# Redis is optional - disable in .env
REDIS_URL=

# Or install and start Redis:
# Linux: sudo service redis-server start
# macOS: brew services start redis
# Windows: Download from redis.io or use Docker
```

### Docker Issues

#### Docker Container Won't Start
```bash
# Check logs
docker-compose logs

# Rebuild containers
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

#### Port Conflicts
```bash
# Edit docker-compose.yml to use different ports
ports:
  - "8000:5000"  # Changed from 5000:5000
```

### Getting More Help

- **Documentation**: See `docs/` directory for detailed guides
- **Issues**: Report bugs at https://github.com/balasunil-8/aegisforgee/issues
- **Security**: For security issues, see SECURITY.md

---

## 🎓 Next Steps

After successful installation:

1. **First-Time Setup**: Read `docs/getting-started/first-time-setup.md`
2. **Learning Paths**: Explore `docs/getting-started/learning-paths.md`
3. **API Documentation**: Review `API_DOCUMENTATION.md`
4. **CTF Challenges**: Start with beginner challenges in CTF mode
5. **Tool Integration**: Set up Postman, Burp Suite, or OWASP ZAP

---

## 📚 Additional Resources

- [Quick Start Guide](QUICKSTART.md)
- [Deployment Guide](DEPLOYMENT_GUIDE.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [API Documentation](API_DOCUMENTATION.md)
- [OWASP Coverage Matrix](OWASP_COVERAGE_MATRIX.md)

---

**Installation complete! Ready to start testing? See [QUICKSTART.md](QUICKSTART.md) for your first steps.**
