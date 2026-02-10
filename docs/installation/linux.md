# 🐧 Linux Installation Guide

Complete installation guide for AegisForge on Linux distributions (Ubuntu, Debian, CentOS, Arch).

---

## 📋 Prerequisites

### System Requirements
- **RAM**: 2GB minimum, 4GB recommended
- **Disk Space**: 2GB free space
- **Internet**: Required for package installation

### Supported Distributions
- Ubuntu 20.04+ / Debian 10+
- CentOS 8+ / RHEL 8+ / Fedora 35+
- Arch Linux
- Other systemd-based distributions

---

## 🚀 Ubuntu/Debian Installation

### Quick Install Script

```bash
# One-line installer
curl -fsSL https://raw.githubusercontent.com/balasunil-8/aegisforgee/main/scripts/install-linux.sh | bash
```

### Manual Installation

#### Step 1: Update System
```bash
sudo apt update && sudo apt upgrade -y
```

#### Step 2: Install Dependencies
```bash
# Core dependencies
sudo apt install -y python3 python3-pip python3-venv git

# Optional: PostgreSQL and Redis
sudo apt install -y postgresql postgresql-contrib redis-server

# Optional: Development tools
sudo apt install -y curl wget build-essential
```

#### Step 3: Clone Repository
```bash
cd ~
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee
```

#### Step 4: Create Virtual Environment
```bash
# Create venv
python3 -m venv venv

# Activate venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip
```

#### Step 5: Install Python Dependencies
```bash
# Core requirements
pip install -r requirements.txt

# Optional: Production features
pip install -r requirements_pro.txt
```

#### Step 6: Configure Environment
```bash
# Copy template
cp .env.example .env

# Edit configuration
nano .env  # or vim, vi, gedit
```

#### Step 7: Initialize Database
```bash
python init_db.py
```

#### Step 8: Start Application
```bash
# Make launcher executable
chmod +x start_pentestlab.sh

# Start application
./start_pentestlab.sh

# Or start manually
python aegisforge_api.py
```

#### Step 9: Access Application
Open browser to: **http://localhost:5000**

---

## 🎩 CentOS/RHEL/Fedora Installation

### Step 1: Install Dependencies

**CentOS/RHEL 8+**:
```bash
# Enable EPEL repository
sudo dnf install -y epel-release

# Install Python and Git
sudo dnf install -y python3 python3-pip python3-devel git

# Optional: PostgreSQL and Redis
sudo dnf install -y postgresql-server postgresql-contrib redis
```

**Fedora**:
```bash
sudo dnf install -y python3 python3-pip python3-devel git postgresql-server redis
```

### Step 2: Continue with Common Steps
```bash
# Clone repository
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure and initialize
cp .env.example .env
python init_db.py

# Start application
python aegisforge_api.py
```

---

## 🔷 Arch Linux Installation

### Step 1: Install Dependencies
```bash
# Update system
sudo pacman -Syu

# Install required packages
sudo pacman -S python python-pip python-virtualenv git

# Optional: PostgreSQL and Redis
sudo pacman -S postgresql redis
```

### Step 2: Setup and Run
```bash
# Clone repository
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure and start
cp .env.example .env
python init_db.py
python aegisforge_api.py
```

---

## 🐳 Docker Installation (All Distributions)

### Prerequisites
Install Docker and Docker Compose:

**Ubuntu/Debian**:
```bash
# Install Docker
curl -fsSL https://get.docker.com | sh

# Install Docker Compose
sudo apt install -y docker-compose

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

**CentOS/RHEL**:
```bash
sudo dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl start docker
sudo systemctl enable docker
```

**Arch Linux**:
```bash
sudo pacman -S docker docker-compose
sudo systemctl start docker
sudo systemctl enable docker
```

### Deploy with Docker

```bash
# Clone repository
git clone https://github.com/balasunil-8/aegisforgee.git
cd aegisforgee

# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

---

## 🔧 PostgreSQL Configuration

### Initialize PostgreSQL

**Ubuntu/Debian**:
```bash
# PostgreSQL is auto-configured
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**CentOS/RHEL**:
```bash
# Initialize database
sudo postgresql-setup --initdb

# Start and enable
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**Arch Linux**:
```bash
# Initialize database cluster
sudo -u postgres initdb -D /var/lib/postgres/data

# Start and enable
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### Create Database

```bash
# Switch to postgres user
sudo -u postgres psql

# Create database and user
CREATE DATABASE aegisforge;
CREATE USER aegisforge WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE aegisforge TO aegisforge;
\q
```

### Update Configuration

Edit `.env`:
```bash
DATABASE_URL=postgresql://aegisforge:secure_password@localhost/aegisforge
```

Initialize:
```bash
python init_db.py
```

---

## 🔴 Redis Configuration

### Start Redis

**All distributions**:
```bash
# Start Redis
sudo systemctl start redis

# Enable on boot
sudo systemctl enable redis

# Test connection
redis-cli ping
# Should return: PONG
```

### Update Configuration

Edit `.env`:
```bash
REDIS_URL=redis://localhost:6379/0
```

---

## 🔐 Security Hardening

### Firewall Configuration

**UFW (Ubuntu/Debian)**:
```bash
# Allow SSH
sudo ufw allow 22/tcp

# Allow application port
sudo ufw allow 5000/tcp

# Enable firewall
sudo ufw enable
```

**firewalld (CentOS/RHEL)**:
```bash
# Allow application port
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --reload
```

### SELinux Configuration (CentOS/RHEL)

```bash
# If using SELinux, allow network connections
sudo setsebool -P httpd_can_network_connect 1
```

---

## 🌐 Systemd Service

Create a systemd service for auto-start:

### Create Service File

```bash
sudo nano /etc/systemd/system/aegisforge.service
```

Add content:
```ini
[Unit]
Description=AegisForge Security Testing Platform
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=youruser
WorkingDirectory=/home/youruser/aegisforgee
Environment="PATH=/home/youruser/aegisforgee/venv/bin"
ExecStart=/home/youruser/aegisforgee/venv/bin/python aegisforge_api.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable aegisforge

# Start service
sudo systemctl start aegisforge

# Check status
sudo systemctl status aegisforge

# View logs
sudo journalctl -u aegisforge -f
```

---

## 🔍 Troubleshooting

### Port Already in Use

```bash
# Find process using port 5000
sudo lsof -i :5000

# Kill process
sudo kill -9 <PID>

# Or use fuser
sudo fuser -k 5000/tcp
```

### Permission Denied

```bash
# Fix file permissions
chmod +x start_pentestlab.sh
chmod 755 aegisforge_api.py

# Fix directory permissions
chmod 755 instance/
```

### Python Module Not Found

```bash
# Activate virtual environment
source venv/bin/activate

# Verify activation (should show venv path)
which python

# Reinstall dependencies
pip install -r requirements.txt
```

### PostgreSQL Connection Failed

```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# Check if port is listening
sudo ss -tlnp | grep 5432

# View PostgreSQL logs
sudo journalctl -u postgresql -f

# Test connection
psql -h localhost -U aegisforge -d aegisforge
```

### Redis Connection Failed

```bash
# Check Redis status
sudo systemctl status redis

# Test connection
redis-cli ping

# Check logs
sudo journalctl -u redis -f
```

### Database Locked Error

```bash
# Stop all Python processes
pkill -f python

# Remove lock file
rm -f instance/aegisforge.db-journal

# Restart application
python aegisforge_api.py
```

---

## 📊 Performance Optimization

### Use Production Server

```bash
# Install gunicorn
pip install gunicorn

# Start with gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 aegisforge_api:app

# With systemd (update service file):
ExecStart=/home/youruser/aegisforgee/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 aegisforge_api:app
```

### Nginx Reverse Proxy

Install Nginx:
```bash
sudo apt install nginx  # Ubuntu/Debian
sudo dnf install nginx  # CentOS/RHEL
```

Configure:
```bash
sudo nano /etc/nginx/sites-available/aegisforge
```

Add:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Enable:
```bash
sudo ln -s /etc/nginx/sites-available/aegisforge /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 🔄 Updates

```bash
# Navigate to directory
cd ~/aegisforgee

# Pull latest changes
git pull origin main

# Activate venv
source venv/bin/activate

# Update dependencies
pip install -r requirements.txt --upgrade

# Update database
python init_db.py

# Restart service
sudo systemctl restart aegisforge
```

---

## 📚 Next Steps

- **Configuration**: Review [docs/getting-started/first-time-setup.md](../getting-started/first-time-setup.md)
- **Security**: Harden your installation for production
- **Monitoring**: Set up logging and monitoring
- **Backup**: Configure automated backups

---

## 🆘 Getting Help

- **Logs**: `sudo journalctl -u aegisforge -f`
- **Issues**: [GitHub Issues](https://github.com/balasunil-8/aegisforgee/issues)
- **Documentation**: [README.md](../../README.md)

---

**Installation complete! Access at http://localhost:5000** 🚀
