# VulnShop Pro - Cloud Deployment Guide

## 🚀 Quick Start (Local Testing)

```bash
# 1. Install dependencies
pip install -r requirements_pro.txt

# 2. Run the application
python vulnshop_pro.py

# 3. Access the dashboard
# Open http://localhost:5000 in your browser

# 4. Test API endpoints
curl http://localhost:5000/api/health
```

---

## ☁️ FREE CLOUD DEPLOYMENT OPTIONS

### **Option 1: Railway.app (RECOMMENDED - Fastest)**

**Why Railway?**
- Free tier: 5GB storage, $5/month credit
- Easy GitHub integration
- Free PostgreSQL database included
- Automatic SSL/HTTPS
- Zero configuration required

**Steps:**

1. **Create Railway account**
   ```
   https://railway.app (sign up with GitHub)
   ```

2. **Connect GitHub repo**
   ```
   New Project → GitHub Repo → authorized-repo
   ```

3. **Add environment variables**
   ```
   Create a railway.json in project root:
   ```

4. **Deploy**
   ```
   git push → Automatic deployment
   ```

5. **Access your app**
   ```
   https://vulnshop-pro-{random}.railway.app
   ```

**Configuration File (railway.json):**
```json
{
  "build": {
    "builder": "nixpacks"
  },
  "deploy": {
    "restartPolicyType": "on_failure",
    "restartPolicyMaxRetries": 5
  }
}
```

---

### **Option 2: Render.com (Alternative)**

**Steps:**

1. **Create Render account**
   ```
   https://render.com (sign up with GitHub)
   ```

2. **Create new Web Service**
   ```
   Dashboard → New → Web Service → Connect GitHub repo
   ```

3. **Configure service**
   ```
   Name: vulnshop-pro
   Environment: Python 3.11
   Build command: pip install -r requirements_pro.txt
   Start command: gunicorn --timeout 120 vulnshop_pro:app
   ```

4. **Add database**
   ```
   Add PostgreSQL database in Environment
   ```

5. **Deploy**
   ```
   Create Web Service → Auto-deploys
   ```

---

### **Option 3: Heroku (Freemium - Coming Soon)**

Heroku is phasing out free tier, but these alternatives are better anyway.

---

## 🐳 Docker Setup (Recommended for All Deployments)

### **Dockerfile**

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements_pro.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements_pro.txt

# Copy application
COPY . .

# Environment variables
ENV FLASK_APP=vulnshop_pro.py
ENV FLASK_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Expose port
EXPOSE 5000

# Run application
CMD gunicorn --worker-class sync --workers 4 --bind 0.0.0.0:5000 --timeout 120 vulnshop_pro:app
```

### **Docker Compose (Local Testing)**

```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=postgresql://vulnshop:password@db:5432/vulnshop_pro
      - FLASK_ENV=development
    depends_on:
      - db
    volumes:
      - .:/app

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=vulnshop
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=vulnshop_pro
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

volumes:
  postgres_data:
```

**Run it:**
```bash
docker-compose up
# Access at http://localhost:5000
```

---

## 🌍 Domain Setup (Custom Domain)

### **Free Domain Options**
- Use subdomain from Railway/Render
- Free domain: freenom.com
- Or use GitHub pages as CDN

### **Custom Domain on Railway**

1. **Buy domain** (Namecheap, GoDaddy, etc.)
2. **Add to Railway**
   ```
   Project Settings → Domains → Add Domain
   ```
3. **Update DNS records**
   ```
   CNAME: your-domain.com → railway.app-reference
   ```

---

## 🔒 Security Configuration

### **Environment Variables (Create .env file)**

```env
# Database
DATABASE_URL=postgresql://user:pass@host:5432/vulnshop_pro

# Flask
FLASK_ENV=production
SECRET_KEY=your-secret-key-here-min-32-chars
JWT_SECRET_KEY=your-jwt-secret-key-here-min-32-chars

# Security
CORS_ORIGINS=https://yourdomain.com
DEBUG=False

# API Keys (for third-party integrations)
POSTMAN_API_KEY=your-key
```

### **Production Checklist**

- [ ] Use strong, unique secret keys (minimum 32 characters)
- [ ] Enable HTTPS/SSL (automatic on Railway/Render)
- [ ] Set DEBUG=False in production
- [ ] Use PostgreSQL (not SQLite)
- [ ] Enable CORS for specific domains only
- [ ] Implement rate limiting
- [ ] Add DDoS protection (Cloudflare)
- [ ] Set up monitoring/logging
- [ ] Implement automated backups
- [ ] Use managed database service
- [ ] Enable Web Application Firewall (WAF)
- [ ] Set up intrusion detection

---

## 📊 Monitoring & Logging

### **Add Logging to vulnshop_pro.py**

```python
import logging
from logging.handlers import RotatingFileHandler

if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/vulnshop_pro.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('VulnShop Pro startup')
```

### **Integrate with Monitoring Services**

- **Free options:**
  - Sentry (error tracking)
  - DataDog free tier
  - CloudWatch (AWS)
  - New Relic (limited free tier)

---

## 📈 Scaling Strategy

### **Phase 1: Single Instance (Current)**
- 1 web server
- Shared database
- File-based cache

### **Phase 2: Horizontal Scaling (10k+ users)**
- Load balancer (Railway/Render handles this)
- Multiple web instances
- PostgreSQL with read replicas
- Redis for caching

### **Phase 3: Advanced (100k+ users)**
- CDN for static assets (Cloudflare)
- Database sharding
- Separate microservices
- Kubernetes orchestration

---

## 🚨 Troubleshooting

### **Issue: Database connection fails**
```bash
# Check DATABASE_URL format
postgresql://username:password@host:port/database
```

### **Issue: Port already in use**
```bash
# Change port in app.run()
app.run(port=5001)
```

### **Issue: Module not found**
```bash
# Install requirements
pip install -r requirements_pro.txt
```

### **Issue: 502 Bad Gateway on Railway**
```
1. Check application logs
2. Increase gunicorn timeout
3. Reduce response size
4. Check memory usage
```

---

## 📚 Next Steps

1. **Test locally**: `python vulnshop_pro.py`
2. **Push to GitHub**: Commit your code
3. **Deploy to Railway**: Connect GitHub repo
4. **Set environment variables** in Railway UI
5. **Monitor logs** in deployment dashboard
6. **Celebrate!** 🎉 Your platform is live

---

## 📞 Support Resources

- **Railway Docs**: https://docs.railway.app
- **Flask Deployment**: https://flask.palletsprojects.com/deployment
- **PostgreSQL Tips**: https://www.postgresql.org/docs
- **Gunicorn Docs**: https://gunicorn.org

---

**VulnShop Pro is now live. Share it with the security community! 🚀**

